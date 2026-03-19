from celery import shared_task
from django.utils import timezone
from .models import Task, Asset, Port, Category, AssetChangeLog, Vulnerability, Alert
from .utils.nmap_scanner import NmapScanner
import ipaddress
import logging
import os

logger = logging.getLogger(__name__)

def _get_vendor_from_mac(mac):
    """
    根据 MAC 地址前缀识别厂商 (OUI 查找)
    """
    if not mac: return ""
    mac = mac.upper().replace(':', '').replace('-', '')[:6]
    
    oui_map = {
        # 虚拟化平台
        '000C29': 'VMware', '005056': 'VMware', '000569': 'VMware',
        '00155D': 'Microsoft Hyper-V', '001C42': 'Parallels', '080027': 'VirtualBox',
        '001A2B': 'Google Cloud', '001630': 'Alibaba Cloud', '00175E': 'Tencent Cloud',
        '00D3C1': 'Huawei Cloud', '0025AE': 'Microsoft Azure', '001DD8': 'KVM/QEMU',
        
        # PC/服务器厂商
        'B4FBE4': 'Apple', '70F395': 'Apple', '0017F2': 'Apple', '3C0754': 'Apple',
        '001C42': 'Apple', '002312': 'Apple', '002436': 'Apple', '00254B': 'Apple',
        'D8CB8A': 'MSI', 'B4E842': 'MSI', '001FC6': 'Lenovo', '001F16': 'Lenovo',
        '00D02D': 'Dell', '001422': 'Dell', '002170': 'Dell', '0021F6': 'Dell',
        '001132': 'Synology', '00089B': 'QNAP', '001627': 'QNAP',
        
        # 网络设备厂商
        'ACE010': 'Huawei', '286ED4': 'Xiaomi', '8CBEBE': 'Xiaomi', '34CE00': 'Xiaomi',
        '00E04C': 'Realtek', 'BC5FF4': 'ASUSTek', '001FC6': 'ASUS', '002215': 'ASUS',
        '001018': 'Cisco', '000DBD': 'Cisco', '0011BB': 'Cisco', '001F6C': 'Cisco',
        '0050BA': 'D-Link', '001018': 'D-Link', '1C7EE5': 'D-Link',
        'FCFBFB': 'TP-Link', '50C7BF': 'TP-Link', 'B09575': 'TP-Link', 'C006C3': 'TP-Link',
        '001D0F': 'Netgear', '00146C': 'Netgear', '001E2A': 'Netgear',
        '001B2F': 'Linksys', '001521': 'Linksys', '001FC2': 'Linksys',
        
        # 服务器厂商
        '002312': 'Supermicro', '001346': 'Supermicro', '0023AE': 'Supermicro',
        '0021F6': 'HP ProLiant', '0021F6': 'HP', '001B78': 'HP', '001A4B': 'HP',
        '001DD8': 'HPE', '001E68': 'HPE', '001F29': 'HPE',
        
        # 移动设备
        '001632': 'Samsung', '0016DC': 'Samsung', '00199E': 'Samsung', '0023D6': 'Samsung',
        '001CB3': 'Huawei', '001E10': 'Huawei', '0022AA': 'Huawei', '0023M0': 'Huawei',
        '0015B1': 'Google', '001632': 'Google', '001EA2': 'Google',
        
        # 物联网/智能设备
        '001632': 'Amazon', '0050F5': 'Amazon', '00FC8B': 'Amazon', '0C47C9': 'Amazon',
        '001A2B': 'Google Nest', '001527': 'Philips Hue', '0017F2': 'Philips',
        
        # 工业设备
        '0011BB': 'Schneider', '001F71': 'Schneider', '000F6A': 'Siemens',
        
        # 其他常见厂商
        '0024E4': 'Brocade', '000A99': 'Arista', '001D46': 'Juniper',
    }
    return oui_map.get(mac, "")

def _get_network_segment(ip_str):
    """
    根据 IP 地址推断网段 (简单推断 /24)
    """
    try:
        ip = ipaddress.ip_interface(f"{ip_str}/24")
        return str(ip.network)
    except Exception:
        return ""

@shared_task
def run_scan(task_id):
    """
    执行扫描任务
    """
    try:
        task = Task.objects.get(id=task_id)
        task.status = 'RUNNING'
        task.save()
        
        logger.info(f"Start scanning task {task.id} for target {task.target}")
        
        # 权限检查提示
        import ctypes
        is_admin = False
        try:
            is_admin = os.getuid() == 0 # Unix
        except AttributeError:
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0 # Windows
            except Exception:
                pass
        
        if not is_admin:
            logger.warning("当前未以管理员权限运行，Nmap 扫描可能无法获取 MAC 地址和厂商信息。")

        scanner = NmapScanner()
        try:
            result = scanner.scan(
                task.target,
                task.scan_type,
                options={
                    'ports': task.ports,
                    'enable_tcp': task.enable_tcp,
                    'enable_udp': task.enable_udp,
                    'tcp_scan': task.tcp_scan,
                    'host_discovery': task.host_discovery,
                    'timing': task.timing,
                    'use_scripts': task.use_scripts,
                    'script_categories': task.script_categories,
                },
            )
        except Exception as e:
            task.status = 'FAILED'
            task.progress = 0
            task.result_summary = f"扫描失败: {str(e)}"
            task.finished_at = timezone.now()
            task.save()
            return f"Task {task_id} failed"

        if not result or 'scan' not in result or not result['scan']:
            task.status = 'FAILED'
            task.result_summary = "未发现活动主机或目标无法访问"
            task.finished_at = timezone.now()
            task.save()
            return f"Task {task_id} no result"

        # 解析结果
        scan_data = result['scan']
        total_ips = len(scan_data)
        processed_ips = 0
        found_hosts = 0
        
        for ip, data in scan_data.items():
            processed_ips += 1
            if total_ips > 0:
                task.progress = int((processed_ips / total_ips) * 100)
                task.save(update_fields=['progress'])
            
            if not data or data.get('status', {}).get('state') != 'up':
                continue
            
            found_hosts += 1
            
            # 提取主机名
            hostnames = data.get('hostnames', [])
            hostname = ''
            for hn in hostnames:
                name = (hn.get('name') or '').strip()
                if name:
                    hostname = name
                    break
            
            # 提取 OS 信息
            os_info = ''
            os_accuracy = 0
            osmatches = data.get('osmatch') or []
            if osmatches:
                best = None
                best_acc = -1
                for m in osmatches:
                    try:
                        acc = int(m.get('accuracy') or 0)
                    except Exception:
                        acc = 0
                    if acc > best_acc:
                        best = m
                        best_acc = acc
                if best:
                    os_info = (best.get('name') or '').strip()
                    os_accuracy = best_acc
            
            # 提取 MAC 地址和厂商
            mac_address = ''
            vendor = ''
            addresses = data.get('addresses', {})
            if 'mac' in addresses:
                mac_address = addresses['mac']
                vendor_map = data.get('vendor', {}) or {}
                if vendor_map:
                    mac_key = (mac_address or '').upper()
                    mac_compact = mac_key.replace(':', '').replace('-', '')
                    vendor = (
                        vendor_map.get(mac_address)
                        or vendor_map.get(mac_key)
                        or vendor_map.get(mac_compact)
                        or _get_vendor_from_mac(mac_address) # 增加备选查找
                        or ''
                    )

            # 检查资产是否存在，记录变更
            asset_obj = Asset.objects.filter(ip_address=ip).first()
            
            # 标准化 OS 信息
            norm_os = _normalize_os(os_info)
            
            if not asset_obj:
                asset_obj = Asset.objects.create(
                    ip_address=ip,
                    hostname=hostname or '',
                    os_info=norm_os or os_info or '',
                    mac_address=mac_address or '',
                    vendor=vendor or '',
                    is_up=data['status']['state'] == 'up',
                    last_scanned=timezone.now(),
                    network_segment=_get_network_segment(ip),
                    discovery_method='ACTIVE'
                )
                AssetChangeLog.objects.create(
                    asset=asset_obj,
                    change_type='新增资产',
                    description=f"发现新资产: {ip}"
                )
                Alert.objects.create(
                    asset=asset_obj,
                    alert_type='NEW_ASSET',
                    severity='MEDIUM',
                    title=f"新资产发现: {ip}",
                    content=f"在扫描任务中发现新资产，IP: {ip}，主机名: {hostname or '未知'}"
                )
            else:
                # 检查状态变更
                is_up = data['status']['state'] == 'up'
                if asset_obj.is_up and not is_up:
                    Alert.objects.create(
                        asset=asset_obj,
                        alert_type='OFFLINE',
                        severity='HIGH',
                        title=f"资产异常下线: {ip}",
                        content=f"资产 {ip} 从 在线 变为 离线 状态。"
                    )
                elif not asset_obj.is_up and is_up:
                    Alert.objects.create(
                        asset=asset_obj,
                        alert_type='SERVICE_CHANGE',
                        severity='LOW',
                        title=f"资产重新上线: {ip}",
                        content=f"资产 {ip} 已恢复在线。"
                    )
                
                # 检查 OS 是否变化（只有准确度高于80%时才更新）
                current_os = norm_os or os_info or ''
                if current_os and os_accuracy >= 80:
                    if asset_obj.os_info != current_os:
                        AssetChangeLog.objects.create(
                            asset=asset_obj,
                            change_type='系统变更',
                            description=f"操作系统从 {asset_obj.os_info} 变更为 {current_os}"
                        )
                    asset_obj.os_info = current_os
                elif not asset_obj.os_info and current_os:
                    asset_obj.os_info = current_os
                
                if hostname:
                    asset_obj.hostname = hostname
                if mac_address:
                    asset_obj.mac_address = mac_address
                if vendor:
                    asset_obj.vendor = vendor
                asset_obj.is_up = data['status']['state'] == 'up'
                asset_obj.last_scanned = timezone.now()
                asset_obj.save()
            
            # 处理端口
            open_ports = 0
            current_ports = {'tcp': set(), 'udp': set()}
            for proto in ['tcp', 'udp']:
                if proto not in data:
                    continue
                for port_num, port_data in data[proto].items():
                    state = (port_data.get('state') or '').lower()
                    is_open = state == 'open'
                    is_open_or_filtered = is_open or (proto == 'udp' and state == 'open|filtered')
                    if not is_open_or_filtered:
                        continue
                    if is_open:
                        open_ports += 1
                    current_ports[proto].add(port_num)

                    service_name = port_data.get('name', '')
                    product = port_data.get('product', '')
                    version = port_data.get('version', '')
                    extrainfo = port_data.get('extrainfo', '')
                    
                    app_fingerprint, is_vulnerable = _fingerprint_service(
                        port_num, proto, service_name, product, version, extrainfo
                    )

                    port_obj, created = Port.objects.update_or_create(
                        asset=asset_obj,
                        port_number=port_num,
                        protocol=proto,
                        defaults={
                            'service_name': service_name,
                            'service_version': f"{product} {version}".strip(),
                            'state': state or 'open',
                            'banner': extrainfo,
                            'app_fingerprint': app_fingerprint,
                            'is_vulnerable_version': is_vulnerable
                        }
                    )

                    # 执行漏洞与风险探测
                    _detect_vulnerabilities(asset_obj, port_obj, port_data)
                    
                    # 处理 Nmap 脚本 (NSE) 扫描结果
                    scripts = port_data.get('script', {})
                    if scripts:
                        for script_id, script_output in scripts.items():
                            _process_nse_result(asset_obj, port_obj, script_id, script_output)

                    if created:
                        label = '开放' if state == 'open' else '可疑'
                        AssetChangeLog.objects.create(
                            asset=asset_obj,
                            change_type='端口变化',
                            description=f"发现新{label}端口: {port_num}/{proto} ({port_obj.service_name})"
                        )

            for proto in ['tcp', 'udp']:
                existing_ports = Port.objects.filter(asset=asset_obj, protocol=proto, state__in=['open', 'open|filtered'])
                for ep in existing_ports:
                    if ep.port_number not in current_ports[proto]:
                        ep.state = 'closed'
                        ep.save()
                        AssetChangeLog.objects.create(
                            asset=asset_obj,
                            change_type='端口变化',
                            description=f"端口已关闭: {ep.port_number}/{proto}"
                        )

            asset_obj.open_ports_count = open_ports
            if not asset_obj.category:
                asset_obj.category = _infer_category(asset_obj, data)
            asset_obj.save()

        task.status = 'COMPLETED'
        task.progress = 100
        task.finished_at = timezone.now()
        task.result_summary = f"成功扫描到 {found_hosts} 个活动主机。"
        task.save()
        
        return f"Task {task_id} completed successfully"

    except Exception as e:
        logger.error(f"Task {task_id} exception: {e}")
        if 'task' in locals():
            task.status = 'FAILED'
            task.result_summary = f"系统错误: {str(e)}"
            task.finished_at = timezone.now()
            task.save()
        return f"Task {task_id} failed with exception"

def _normalize_os(raw_os):
    if not raw_os:
        return ""
    
    raw_os_lower = raw_os.lower()
    
    # Windows
    if 'windows' in raw_os_lower:
        if any(x in raw_os_lower for x in ['server 2008', 'server 2012', 'server 2016', 'server 2019', 'server 2022']):
            return "Windows Server"
        if any(x in raw_os_lower for x in ['10', '11']):
            return "Windows PC"
        return "Windows"
    
    # Linux
    if 'linux' in raw_os_lower or 'ubuntu' in raw_os_lower or 'debian' in raw_os_lower or 'centos' in raw_os_lower:
        if 'ubuntu' in raw_os_lower: return "Ubuntu Linux"
        if 'centos' in raw_os_lower: return "CentOS Linux"
        if 'debian' in raw_os_lower: return "Debian Linux"
        if 'fedora' in raw_os_lower: return "Fedora Linux"
        if any(x in raw_os_lower for x in ['red hat', 'redhat']): return "Red Hat Linux"
        if 'kali' in raw_os_lower: return "Kali Linux"
        if 'arch' in raw_os_lower: return "Arch Linux"
        return "Linux"
    
    # macOS
    if any(x in raw_os_lower for x in ['macos', 'os x', 'darwin', 'apple']):
        return "macOS"
    
    # Unix
    if any(x in raw_os_lower for x in ['freebsd', 'openbsd', 'netbsd', 'solaris', 'sunos', 'aix', 'hp-ux']):
        return "Unix"
        
    # Embedded / Network Devices
    if any(x in raw_os_lower for x in ['embedded', 'rtos', 'vxworks', 'qnx', 'cisco ios', 'huawei vrp', 'junos', 'routeros']):
        return "Embedded/Network OS"
        
    return raw_os

def _infer_category(asset_obj, host_data):
    name = '服务器' # 默认
    os_info = (asset_obj.os_info or '').lower()
    vendor = (asset_obj.vendor or '').lower()
    hostname = (asset_obj.hostname or '').lower()
    
    ports = set()
    service_names = set()
    for proto in ('tcp', 'udp'):
        for p, pd in (host_data.get(proto) or {}).items():
            state = (pd.get('state') or '').lower()
            if state in {'open', 'open|filtered'}:
                ports.add(int(p))
                if pd.get('name'):
                    service_names.add(pd.get('name').lower())

    # 1. 网络设备 (优先匹配)
    net_vendors = ['cisco', 'huawei', 'h3c', 'juniper', 'arista', 'mikrotik', 'tp-link', 'd-link', 'fortinet', 'palo alto', 'ruijie', 'tenda']
    net_keywords = ['switch', 'router', 'firewall', 'gateway', 'bridge', 'ap']
    if any(x in vendor for x in net_vendors) or any(x in hostname for x in net_keywords) or any(x in os_info for x in ['ios', 'vrp', 'junos', 'routeros']):
        name = '网络设备'
    
    # 2. 打印机
    printer_vendors = ['hp', 'epson', 'canon', 'brother', 'xerox', 'ricoh', 'lexmark', 'kyocera', 'konica', 'minolta']
    if any(x in vendor for x in printer_vendors) or ports & {9100, 515, 631} or 'ipp' in service_names:
        name = '打印机'
        
    # 3. 摄像头 / 安防设备
    camera_vendors = ['hikvision', 'dahua', 'uniview', 'axis', 'honeywell', 'hanwha', 'tiandy']
    camera_keywords = ['camera', 'nvr', 'dvr', 'ipc', 'video']
    if any(x in vendor for x in camera_vendors) or any(x in hostname for x in camera_keywords) or ports & {554, 8000, 37777, 8081}:
        name = '摄像头'
        
    # 4. VoIP / 电话设备
    voip_vendors = ['polycom', 'yealink', 'avaya', 'grandstream', 'gigaset', 'snom']
    if any(x in vendor for x in voip_vendors) or ports & {5060, 5061, 2000, 1720}:
        name = 'VoIP设备'
        
    # 5. IoT / 智能设备
    iot_vendors = ['xiaomi', 'tuya', 'broadlink', 'philips', 'sonoff', 'ikea']
    if any(x in vendor for x in iot_vendors) or ports & {1883, 8883, 5683}:
        name = 'IoT设备'

    # 6. PC / 工作站
    if 'windows pc' in os_info or 'macos' in os_info:
        name = 'PC'
    elif 'windows' in os_info and not 'server' in os_info:
        # 如果是 Windows 且没有 server 关键字，但有常见桌面端口或没有常见服务器端口
        if ports & {3389} and not (ports & {3306, 5432, 1433, 1521}):
            name = 'PC'

    # 7. 数据库 (作为特定服务器类型)
    if name == '服务器' and (ports & {3306, 5432, 1521, 1433, 27017, 6379, 9200}):
        name = '数据库'
    
    # 8. Web服务 (作为特定服务器类型)
    if name == '服务器' and (ports & {80, 443, 8080, 8443, 8000, 8001, 8002}):
        name = 'Web服务'

    try:
        return Category.objects.get_or_create(name=name, defaults={'description': ''})[0]
    except Exception:
        return None

def _fingerprint_service(port, proto, name, product, version, extrainfo):
    """
    进行详细的服务与应用指纹识别，并标记风险版本
    """
    fingerprint = ""
    is_vulnerable = False
    
    # 转换为小写以便匹配
    name_l = name.lower()
    product_l = product.lower()
    version_l = version.lower()
    info_l = extrainfo.lower()
    
    # 1. Web 中间件识别
    if name_l in ['http', 'https', 'ssl/http', 'http-alt']:
        if 'nginx' in product_l:
            fingerprint = f"Nginx/{version}" if version else "Nginx"
        elif 'apache' in product_l:
            if 'tomcat' in product_l or 'tomcat' in info_l:
                fingerprint = f"Apache Tomcat/{version}" if version else "Apache Tomcat"
            else:
                fingerprint = f"Apache HTTPD/{version}" if version else "Apache HTTPD"
        elif 'iis' in product_l or 'microsoft-iis' in product_l:
            fingerprint = f"IIS/{version}" if version else "IIS"
        elif 'jetty' in product_l:
            fingerprint = f"Jetty/{version}" if version else "Jetty"
        elif 'weblogic' in product_l or 'weblogic' in info_l:
            fingerprint = f"WebLogic/{version}" if version else "WebLogic"
        elif 'websphere' in product_l:
            fingerprint = f"WebSphere/{version}" if version else "WebSphere"
        elif 'jboss' in product_l or 'wildfly' in product_l:
            fingerprint = f"JBoss/WildFly"
            
    # 2. 数据库识别
    elif 'mysql' in product_l or name_l == 'mysql':
        fingerprint = f"MySQL/{version}" if version else "MySQL"
    elif 'postgresql' in product_l or name_l == 'postgresql':
        fingerprint = f"PostgreSQL/{version}" if version else "PostgreSQL"
    elif 'oracle' in product_l or name_l == 'oracle':
        fingerprint = f"Oracle Database/{version}" if version else "Oracle"
    elif 'microsoft sql server' in product_l or 'ms-sql' in name_l:
        fingerprint = f"MS-SQL Server/{version}" if version else "MS-SQL"
    elif 'redis' in product_l or name_l == 'redis':
        fingerprint = f"Redis/{version}" if version else "Redis"
    elif 'mongodb' in product_l or name_l == 'mongodb':
        fingerprint = f"MongoDB/{version}" if version else "MongoDB"
    elif 'elasticsearch' in product_l or 'elastic' in product_l:
        fingerprint = f"Elasticsearch/{version}" if version else "Elasticsearch"

    # 3. 常见框架与应用识别 (基于 extrainfo 或 product)
    if not fingerprint:
        if 'php' in product_l or 'php' in info_l:
            fingerprint = "PHP Environment"
        elif 'wordpress' in info_l:
            fingerprint = "WordPress CMS"
        elif 'shiroutil' in info_l or 'shiro' in info_l:
            fingerprint = "Apache Shiro"
        elif 'spring' in info_l:
            fingerprint = "Spring Framework"
        elif 'struts' in info_l:
            fingerprint = "Apache Struts2"

    # 4. 远程管理与文件服务
    if not fingerprint:
        if name_l == 'ssh' or 'openssh' in product_l:
            fingerprint = f"OpenSSH/{version}" if version else "SSH"
        elif name_l == 'ftp' or 'vsftpd' in product_l or 'proftpd' in product_l:
            fingerprint = f"FTP Service ({product})" if product else "FTP"
        elif name_l == 'microsoft-ds' or name_l == 'netbios-ssn' or 'samba' in product_l:
            fingerprint = "SMB/Samba"

    # 5. 版本精确识别与风险标记 (弱版本识别示例)
    # 这里可以维护一个已知高危版本的列表
    if version:
        # 示例：标记一些已知的过时或高危版本
        vulnerable_patterns = [
            r'1\.[0-7]\.', r'0\.', # 通用的老旧 0.x 或 1.0-1.7 版本
            r'2\.0\.', r'2\.1\.', r'2\.2\.', # 常见的 2.0-2.2 过时版本
            r'5\.5\.', r'5\.6\.', # MySQL 5.5/5.6 等
            r'2\.3\.[0-9]', # Struts2 某些漏洞版本范围
        ]
        import re
        for pattern in vulnerable_patterns:
            if re.search(pattern, version):
                is_vulnerable = True
                break
        
        # 针对特定产品的特定版本标记
        if 'nginx' in product_l and ('1.10' in version or '1.12' in version):
            is_vulnerable = True
        if 'apache' in product_l and '2.2' in version:
            is_vulnerable = True
        if 'php' in product_l and version.startswith('5.'):
            is_vulnerable = True
            
    # 如果还是没识别出指纹，用 product 代替
    if not fingerprint and product:
        fingerprint = f"{product}/{version}".strip('/') if version else product

    return fingerprint, is_vulnerable

def _detect_vulnerabilities(asset, port, port_data):
    """
    针对单个开放端口执行漏洞与风险探测
    """
    port_num = port.port_number
    service = (port.service_name or '').lower()
    product = (port_data.get('product') or '').lower()
    version = (port_data.get('version') or '').lower()
    extrainfo = (port_data.get('extrainfo') or '').lower()
    
    # 定义通用的漏洞创建辅助函数
    def add_vuln(name, severity, description, solution=None, cve_id=None):
        Vulnerability.objects.update_or_create(
            asset=asset,
            port=port,
            name=name,
            defaults={
                'severity': severity,
                'description': description,
                'solution': solution or '请联系管理员修复或更新至最新安全版本。',
                'cve_id': cve_id
            }
        )
        # 高危风险触发告警
        if severity in ['HIGH', 'CRITICAL']:
            Alert.objects.get_or_create(
                asset=asset,
                alert_type='VULNERABILITY',
                severity=severity,
                title=f"发现{severity}风险: {name}",
                content=f"在资产 {asset.ip_address} 的端口 {port.port_number} 上检测到风险：{description}",
                status='UNREAD'
            )

    # 1. 配置风险识别 (不必要端口 / 默认服务)
    risky_ports = {
        21: ("FTP 服务明文传输风险", "MEDIUM", "检测到 21 端口开放 FTP 服务，FTP 协议采用明文传输，存在账号密码被嗅探的风险。"),
        23: ("Telnet 服务明文传输风险", "HIGH", "检测到 23 端口开放 Telnet 服务，该协议极其不安全，建议关闭并改用 SSH。"),
        445: ("SMB 服务暴露风险", "HIGH", "445 端口 (SMB) 直接暴露在公网或大网环境，极易受到永恒之蓝 (EternalBlue) 等漏洞攻击。"),
        3389: ("RDP 远程桌面暴露", "MEDIUM", "检测到 Windows RDP 远程桌面服务开放。"),
    }
    if port_num in risky_ports:
        name, sev, desc = risky_ports[port_num]
        add_vuln(name, sev, desc)

    # 2. 未授权访问探测 (常见数据库和中间件)
    if port_num == 6379:
        add_vuln("Redis 未授权访问/弱口令风险", "CRITICAL", "Redis 服务通常默认不带密码，若未配置密码或存在弱口令，攻击者可直接控制数据库甚至获取系统权限。", "配置 requirepass 参数并限制监听 IP。")
    elif port_num == 27017:
        add_vuln("MongoDB 未授权访问风险", "HIGH", "检测到 MongoDB 默认端口开放，可能存在未授权访问风险。")
    elif port_num == 9200:
        add_vuln("Elasticsearch 未授权访问风险", "HIGH", "Elasticsearch 默认不开启认证，暴露在网络中会导致数据泄露。")
    elif port_num == 2181:
        add_vuln("Zookeeper 未授权访问风险", "HIGH", "Zookeeper 默认无权限控制。")

    # 3. 常见高危漏洞指纹探测
    # Log4j2
    if any(x in extrainfo or x in product for x in ['java', 'spring', 'solr', 'flink', 'log4j']):
        add_vuln("潜在 Log4j2 远程代码执行风险", "CRITICAL", "该服务基于 Java 环境，可能受到 CVE-2021-44228 (Log4j2) 漏洞影响。", "更新 log4j 至 2.17.1 以上版本或禁用相关查找功能。", "CVE-2021-44228")

    # Shiro
    if 'rememberme' in extrainfo or 'shiro' in extrainfo:
        add_vuln("Apache Shiro 反序列化风险", "CRITICAL", "检测到 Apache Shiro 特征，可能存在默认 Key 导致的远程代码执行漏洞。", "更换默认 Key 并升级至安全版本。", "CVE-2016-4437")

    # Struts2
    if '.action' in extrainfo or 'struts2' in extrainfo:
        add_vuln("Apache Struts2 潜在漏洞风险", "HIGH", "检测到 Struts2 框架特征，请检查是否存在 S2-045, S2-057 等已知漏洞。")

    # Web 中间件漏洞 (基于版本)
    if 'nginx' in product and version:
        if '1.1' in version and int(version.split('.')[1]) <= 10:
            add_vuln("Nginx 旧版本已知漏洞风险", "MEDIUM", f"检测到 Nginx {version}，该版本可能存在已知安全漏洞。")
    
    # 4. 弱口令风险标记 (通用提示)
    weak_cred_services = ['ssh', 'mysql', 'mssql', 'postgresql', 'ftp', 'vnc', 'rdp']
    if any(x in service or x in product for x in weak_cred_services):
        add_vuln(f"{service.upper()} 弱口令风险检测", "HIGH", f"检测到 {service} 服务。弱口令是系统被入侵的首要原因，请务必确保该服务不使用默认密码或简单密码。", "强制执行复杂的口令策略，建议启用多因素认证。")

def _process_nse_result(asset, port, script_id, output):
    """
    处理 Nmap 脚本 (NSE) 的扫描结果，并生成真实的漏洞和告警
    """
    severity = 'LOW'
    title = ""
    description = ""
    solution = ""
    cve_id = None
    
    output_l = output.lower()
    
    # 1. 常见漏洞脚本 (vuln 类别)
    if 'vulnerable' in output_l or 'state: vulnerable' in output_l:
        severity = 'HIGH'
        if 'critical' in output_l: severity = 'CRITICAL'
        
        title = f"NSE 探测到高危漏洞: {script_id}"
        description = f"Nmap 脚本 {script_id} 检测到资产存在漏洞。原始输出: {output[:200]}..."
        
        # 提取 CVE 编号 (如果存在)
        import re
        cve_match = re.search(r'CVE-\d{4}-\d+', output)
        if cve_match:
            cve_id = cve_match.group(0)
            
        solution = "请根据 CVE 编号查找官方补丁或加固方案，并立即更新系统。"

    # 2. 未授权访问 (auth 类别)
    elif any(x in script_id for x in ['auth', 'empty-password', 'unauth']):
        severity = 'CRITICAL'
        title = f"检测到未授权访问风险: {script_id}"
        description = f"脚本 {script_id} 确认该服务存在未授权访问或空口令风险。输出: {output}"
        solution = "配置强口令认证，限制访问源 IP，或在配置文件中禁用匿名访问。"

    # 3. 信息泄露
    elif 'info' in script_id or 'enum' in script_id:
        severity = 'MEDIUM'
        title = f"敏感信息泄露: {script_id}"
        description = f"脚本 {script_id} 提取到了系统的敏感信息。输出: {output[:300]}"
        solution = "隐藏服务版本信息，关闭不必要的信息查询接口。"

    if title:
        Vulnerability.objects.update_or_create(
            asset=asset,
            port=port,
            name=title,
            defaults={
                'severity': severity,
                'description': description,
                'solution': solution,
                'cve_id': cve_id
            }
        )
        
        if severity in ['HIGH', 'CRITICAL']:
            Alert.objects.get_or_create(
                asset=asset,
                alert_type='VULNERABILITY',
                severity=severity,
                title=f"实时探测风险: {title}",
                content=description,
                status='UNREAD'
            )

