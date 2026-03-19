import json

from django.conf import settings
from django.utils import timezone

from ..models import Asset, AssetChangeLog, PassiveEvent, Alert, Port, Category


def ingest_event(payload, source=None):
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")

    event_type = (payload.get("event_type") or payload.get("type") or "LOG").upper()
    if event_type not in {"DNS", "HTTP", "TLS", "LOG", "SMB", "DB", "REMOTE"}:
        event_type = "LOG"

    src_ip = payload.get("src_ip") or payload.get("src") or payload.get("client_ip")
    dst_ip = payload.get("dst_ip") or payload.get("dst") or payload.get("server_ip")
    src_port = _to_int(payload.get("src_port") or payload.get("client_port"))
    dst_port = _to_int(payload.get("dst_port") or payload.get("server_port"))

    hostname = payload.get("hostname") or payload.get("host") or payload.get("domain") or payload.get("sni")
    url = payload.get("url")
    method = payload.get("method")
    status_code = _to_int(payload.get("status") or payload.get("status_code"))
    user_agent = payload.get("user_agent") or payload.get("ua")
    banner = payload.get("banner") or payload.get("server_header")

    # 1. 资产发现与补全
    asset_ip = payload.get("asset_ip") or payload.get("asset") or src_ip
    mac = payload.get("mac") or payload.get("src_mac")
    vendor = payload.get("vendor") or payload.get("src_vendor")
    
    asset = _get_or_create_asset(asset_ip, hostname, mac, vendor)

    if not asset:
        return None

    # 2. 增强分析：识别开放服务与端口 (自动同步至 Port 模型)
    if dst_port and dst_ip == asset.ip_address:
        _update_port_info(asset, dst_port, event_type, banner)

    # 3. 增强分析：识别应用指纹与操作系统
    if user_agent and not asset.os_info:
        os_guess = _guess_os_from_ua(user_agent)
        if os_guess:
            asset.os_info = os_guess
            asset.save()
            AssetChangeLog.objects.create(asset=asset, change_type="被动发现", description=f"通过流量识别 OS: {os_guess}")

    # 4. 增强分析：自动分类逻辑
    _reclassify_asset_passively(asset, event_type, dst_port, hostname)

    # 5. 威胁与风险检测
    if event_type == "DNS" and hostname:
        _check_malicious_dns(asset, hostname)
    
    # 基于识别出的版本进行风险标记
    if banner:
        from .tasks import _fingerprint_service
        _, is_vuln = _fingerprint_service(dst_port or 0, 'tcp', event_type.lower(), '', '', banner)
        if is_vuln:
            Alert.objects.get_or_create(
                asset=asset,
                alert_type='VULNERABILITY',
                severity='HIGH',
                title=f"被动发现风险版本: {event_type}",
                defaults={'content': f"资产 {asset.ip_address} 运行的服务 {event_type} (端口 {dst_port}) 识别为风险版本。Banner: {banner}"}
            )
    
    _check_passive_risks(asset, event_type, dst_port, payload)

    now = timezone.now()
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    recent = PassiveEvent.objects.filter(
        event_type=event_type,
        src_ip=src_ip or None,
        dst_ip=dst_ip or None,
        dst_port=dst_port,
        hostname=hostname or None,
        url=url or None,
        method=method or None,
        status_code=status_code,
        user_agent=user_agent or None,
    ).order_by("-last_seen").first()

    if recent and (now - recent.last_seen).total_seconds() <= 300:
        recent.count = (recent.count or 1) + 1
        recent.raw = raw
        recent.source = source or recent.source
        recent.save()
        return recent

    return PassiveEvent.objects.create(
        asset=asset,
        event_type=event_type,
        source=source,
        src_ip=src_ip or None,
        dst_ip=dst_ip or None,
        src_port=src_port,
        dst_port=dst_port,
        hostname=hostname or None,
        url=url or None,
        method=method or None,
        status_code=status_code,
        user_agent=user_agent or None,
        raw=raw,
    )


def validate_ingest_token(request):
    expected = getattr(settings, "PASSIVE_INGEST_TOKEN", None)
    if not expected:
        return True
    token = request.headers.get("X-INGEST-TOKEN") or request.META.get("HTTP_X_INGEST_TOKEN")
    return token == expected


def _get_or_create_asset(ip, hostname=None, mac=None, vendor=None):
    if not ip:
        return None
    asset = Asset.objects.filter(ip_address=ip).first()
    if not asset:
        asset = Asset.objects.create(
            ip_address=ip, 
            hostname=hostname or "",
            mac_address=mac_address or "",
            vendor=vendor or "",
            discovery_method='PASSIVE'
        )
        AssetChangeLog.objects.create(asset=asset, change_type="被动发现", description=f"被动发现新资产: {ip}")
        Alert.objects.create(
            asset=asset,
            alert_type='NEW_ASSET',
            severity='HIGH',
            title=f"被动探测发现陌生设备: {ip}",
            content=f"在被动监听流量中发现新 IP 地址: {ip}，MAC: {mac or '未知'}，可能存在非法接入。"
        )
        return asset
    
    # 更新已有资产信息
    updated = False
    if hostname and not asset.hostname:
        asset.hostname = hostname
        updated = True
    if mac and not asset.mac_address:
        asset.mac_address = mac
        updated = True
    if vendor and not asset.vendor:
        asset.vendor = vendor
        updated = True
        
    if updated:
        asset.save()
        AssetChangeLog.objects.create(asset=asset, change_type="被动发现", description="被动补全资产硬件信息")
        
    return asset


def _guess_os_from_ua(ua):
    """
    通过 HTTP User-Agent 简单识别操作系统
    """
    ua = ua.lower()
    if "windows nt 10.0" in ua: return "Windows 10/11"
    if "windows nt 6.1" in ua: return "Windows 7"
    if "iphone" in ua: return "iOS (iPhone)"
    if "android" in ua: return "Android"
    if "macintosh" in ua: return "macOS"
    if "linux" in ua: return "Linux"
    return None


def _check_malicious_dns(asset, hostname):
    """
    检测恶意的 DNS 探测行为 (示例)
    """
    malicious_keywords = ['cobaltstrike', 'metasploit', 'tor-exit', 'mining', 'poker', 'casino']
    hostname_l = hostname.lower()
    
    if any(kw in hostname_l for kw in malicious_keywords):
        Alert.objects.get_or_create(
            asset=asset,
            alert_type='PROBE',
            severity='CRITICAL',
            title=f"检测到恶意域名请求: {hostname}",
            defaults={
                'content': f"资产 {asset.ip_address if asset else '未知'} 尝试请求可疑域名 {hostname}，可能存在受控或非法连接风险。"
            }
        )


def _update_port_info(asset, port_num, event_type, banner=None):
    """
    通过流量被动发现开放端口并更新指纹
    """
    from .tasks import _fingerprint_service
    
    service_name = event_type.lower()
    if event_type == "HTTP" and port_num == 443: service_name = "https"
    
    # 获取指纹
    fp, is_vulnerable = _fingerprint_service(port_num, 'tcp', service_name, '', '', banner or '')
    
    port_obj, created = Port.objects.update_or_create(
        asset=asset,
        port_number=port_num,
        protocol='tcp',
        defaults={
            'service_name': service_name,
            'state': 'open',
            'banner': banner or '',
            'app_fingerprint': fp or asset.hostname,
            'is_vulnerable_version': is_vulnerable
        }
    )
    
    if created:
        AssetChangeLog.objects.create(
            asset=asset, 
            change_type="端口变化", 
            description=f"流量监听发现新开放端口: {port_num}/tcp ({service_name})"
        )
        # 更新资产的开放端口总数
        asset.open_ports_count = asset.ports.filter(state='open').count()
        asset.save()


def _reclassify_asset_passively(asset, event_type, port, hostname):
    """
    根据流量特征被动重新分类资产
    """
    if asset.category and asset.category.name != "服务器": # 已有精确分类则不覆盖
        return

    new_cat = None
    hostname_l = (hostname or "").lower()
    
    # 1. 识别 IoT/摄像头
    if "hikvision" in hostname_l or "dahua" in hostname_l:
        new_cat = "摄像头"
    # 2. 识别网络设备
    elif "gateway" in hostname_l or "router" in hostname_l or port in [161, 162]:
        new_cat = "网络设备"
    # 3. 识别 PC
    elif "iphone" in hostname_l or "android" in hostname_l:
        new_cat = "PC"
    # 4. 识别数据库
    elif event_type == "DB" or port in [3306, 6379, 5432, 27017, 9200]:
        new_cat = "数据库"
    # 5. 识别 Web 服务
    elif event_type == "HTTP" or port in [80, 443, 8080]:
        new_cat = "Web服务"

    if new_cat:
        cat_obj, _ = Category.objects.get_or_create(name=new_cat)
        if asset.category != cat_obj:
            asset.category = cat_obj
            asset.save()
            AssetChangeLog.objects.create(asset=asset, change_type="被动发现", description=f"根据流量行为识别资产类型: {new_cat}")


def _check_passive_risks(asset, event_type, port, payload):
    """
    被动风险监测
    """
    # 1. 非标准端口运行敏感服务
    if event_type == "HTTP" and port not in [80, 443, 8080, 8443, 8000]:
        Alert.objects.get_or_create(
            asset=asset,
            alert_type='PORT_CHANGE',
            severity='MEDIUM',
            title=f"非标准端口 Web 服务: {port}",
            defaults={'content': f"资产 {asset.ip_address} 在非标准端口 {port} 上运行 Web 服务，可能存在隐蔽入口。"}
        )
    
    # 2. 弱协议检测
    if event_type == "LOG" and port == 23: # Telnet
        Alert.objects.get_or_create(
            asset=asset,
            alert_type='VULNERABILITY',
            severity='HIGH',
            title="检测到不安全的 Telnet 流量",
            defaults={'content': f"资产 {asset.ip_address} 正在使用明文 Telnet 协议，建议替换为 SSH。"}
        )


def _to_int(value):
    if value is None or value == "":
        return None
    try:
        return int(value)
    except Exception:
        return None
