
import logging
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
from .passive_ingest import ingest_event
import threading

logger = logging.getLogger(__name__)

class TrafficSniffer:
    """
    基于 Scapy 的实时流量嗅探器，用于被动资产发现与服务识别
    """
    def __init__(self, interface=None):
        self.interface = interface
        self.running = False
        self.thread = None

    def _packet_callback(self, packet):
        try:
            if not packet.haslayer(IP):
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # 尝试获取源 MAC 地址 (仅限本地二层流量)
            from scapy.all import Ether
            src_mac = None
            if packet.haslayer(Ether):
                src_mac = packet[Ether].src

            payload = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "mac": src_mac, # 传入 MAC 地址
                "source": "sniffer"
            }

            # 1. DNS 探测
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                payload.update({
                    "event_type": "DNS",
                    "hostname": query,
                    "type": "DNS"
                })
                ingest_event(payload, source="sniffer")

            # 2. HTTP 探测 (简单的指纹提取)
            elif packet.haslayer(TCP) and packet.haslayer(Raw):
                dst_port = packet[TCP].dport
                src_port = packet[TCP].sport
                try:
                    raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                except:
                    raw_data = ""
                
                # HTTP 请求识别
                if any(x in raw_data for x in ["GET ", "POST ", "HTTP/1.1", "HTTP/1.0"]):
                    lines = raw_data.split('\r\n')
                    hostname = ""
                    user_agent = ""
                    server_header = ""
                    for line in lines:
                        if line.startswith("Host: "):
                            hostname = line.split(": ")[1]
                        elif line.startswith("User-Agent: "):
                            user_agent = line.split(": ")[1]
                        elif line.startswith("Server: "):
                            server_header = line.split(": ")[1]
                    
                    payload.update({
                        "event_type": "HTTP",
                        "dst_port": dst_port,
                        "src_port": src_port,
                        "hostname": hostname,
                        "user_agent": user_agent,
                        "banner": server_header,
                        "type": "HTTP"
                    })
                    ingest_event(payload, source="sniffer")

                # SSH 识别与版本提取
                elif dst_port == 22 or src_port == 22:
                    if raw_data.startswith("SSH-"):
                        payload.update({
                            "event_type": "REMOTE",
                            "dst_port": dst_port,
                            "banner": raw_data.split('\r\n')[0],
                            "type": "SSH"
                        })
                        ingest_event(payload, source="sniffer")

                # FTP/SMTP 识别与 Banner 提取
                elif dst_port in [21, 25]:
                    if re.match(r'^\d{3} ', raw_data):
                        payload.update({
                            "event_type": "REMOTE",
                            "dst_port": dst_port,
                            "banner": raw_data.split('\r\n')[0],
                            "type": "FTP" if dst_port == 21 else "SMTP"
                        })
                        ingest_event(payload, source="sniffer")

                # TLS SNI 提取 (简易实现)
                elif dst_port == 443 or src_port == 443:
                    # 查找 TLS Client Hello 中的 SNI
                    # 这里使用简单的字节匹配
                    if b"\x16\x03" in packet[Raw].load: # TLS Handshake
                        payload.update({
                            "event_type": "TLS",
                            "dst_port": dst_port,
                            "src_port": src_port,
                            "type": "TLS"
                        })
                        ingest_event(payload, source="sniffer")

                # SMB 识别
                elif dst_port == 445:
                    payload.update({
                        "event_type": "SMB",
                        "dst_port": dst_port,
                        "type": "SMB"
                    })
                    ingest_event(payload, source="sniffer")

                # 数据库识别 (MySQL/Redis)
                elif dst_port in [3306, 6379]:
                    payload.update({
                        "event_type": "DB",
                        "dst_port": dst_port,
                        "type": "DB"
                    })
                    ingest_event(payload, source="sniffer")

            # 3. 基础 IP 发现 (通用日志)
            else:
                # 仅记录新的 IP 交互，避免日志爆炸
                # ingest_event 会自动处理资产去重和静默期
                payload.update({
                    "event_type": "LOG",
                    "type": "LOG"
                })
                ingest_event(payload, source="sniffer")

        except Exception as e:
            # 忽略解析错误
            pass

    def start(self):
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run_sniff, daemon=True)
        self.thread.start()
        logger.info(f"Traffic Sniffer started on interface: {self.interface or 'default'}")

    def _run_sniff(self):
        try:
            sniff(iface=self.interface, prn=self._packet_callback, store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            logger.error(f"Sniffer error: {e}")
            self.running = False

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        logger.info("Traffic Sniffer stopped")

# 全局嗅探器实例
_global_sniffer = None
_sniffer_lock = threading.Lock()

def get_sniffer():
    global _global_sniffer
    with _sniffer_lock:
        if _global_sniffer is None:
            _global_sniffer = TrafficSniffer()
        return _global_sniffer

def start_passive_monitoring(interface=None):
    sniffer = get_sniffer()
    if interface:
        sniffer.interface = interface
    sniffer.start()
    return sniffer.running

def stop_passive_monitoring():
    sniffer = get_sniffer()
    sniffer.stop()
    return not sniffer.running

def get_sniffer_status():
    sniffer = get_sniffer()
    return sniffer.running
