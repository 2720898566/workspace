from django.core.management.base import BaseCommand, CommandError

from scanner.utils.passive_ingest import ingest_event


class Command(BaseCommand):
    help = "被动抓包监听（DNS/HTTP/TLS SNI）并写入被动探测事件库"

    def add_arguments(self, parser):
        parser.add_argument("--iface", default=None)
        parser.add_argument("--filter", default="udp port 53 or tcp")
        parser.add_argument("--pcap", default=None)
        parser.add_argument("--count", type=int, default=0)
        parser.add_argument("--associate", choices=["auto", "src", "dst"], default="auto")
        parser.add_argument("--http-strict-port", action="store_true", default=False)
        parser.add_argument("--tls-strict-port", action="store_true", default=False)

    def handle(self, *args, **options):
        try:
            from scapy.all import sniff, IP, IPv6, UDP, TCP, DNS, DNSQR, Raw
            from scapy.utils import PcapReader
        except Exception as e:
            raise CommandError("未安装 scapy。请先执行：pip install scapy，并在 Windows 安装 Npcap（勾选 WinPcap API-compatible）。") from e

        iface = options["iface"]
        bpf = options["filter"]
        pcap = options["pcap"]
        count = options["count"]
        verbosity = int(options.get("verbosity", 1))
        associate = options["associate"]
        http_strict_port = bool(options["http_strict_port"])
        tls_strict_port = bool(options["tls_strict_port"])

        self.stdout.write(f"Passive sniffer started. iface={iface or '-'} pcap={pcap or '-'}")
        if bpf:
            self.stdout.write(f"BPF filter: {bpf}")
        if not pcap and not iface:
            self.stdout.write("提示：未指定 --iface，将由 scapy 自动选择默认网卡。")
        self.stdout.write("按 Ctrl+C 停止监听。")

        stats = {"DNS": 0, "HTTP": 0, "TLS": 0, "OTHER": 0}
        seen_packets = 0

        def pick_asset_ip(src_ip, dst_ip):
            if associate == "src":
                return src_ip
            if associate == "dst":
                return dst_ip
            src_private = _is_private_ip(src_ip)
            dst_private = _is_private_ip(dst_ip)
            if src_private and not dst_private:
                return src_ip
            if dst_private and not src_private:
                return dst_ip
            return src_ip

        def get_ip(pkt):
            if pkt.haslayer(IP):
                return pkt[IP].src, pkt[IP].dst
            if pkt.haslayer(IPv6):
                return pkt[IPv6].src, pkt[IPv6].dst
            return None, None

        def on_packet(pkt):
            nonlocal seen_packets
            seen_packets += 1
            src_ip, dst_ip = get_ip(pkt)
            if not src_ip or not dst_ip:
                return
            asset_ip = pick_asset_ip(src_ip, dst_ip)

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.haslayer(UDP):
                qname = pkt[DNSQR].qname
                try:
                    hostname = qname.decode("utf-8", errors="ignore").rstrip(".")
                except Exception:
                    hostname = str(qname).rstrip(".")
                ingest_event(
                    {
                        "event_type": "DNS",
                        "asset_ip": asset_ip,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": int(pkt[UDP].sport),
                        "dst_port": int(pkt[UDP].dport),
                        "hostname": hostname,
                    },
                    source="sniffer",
                )
                stats["DNS"] += 1
                if verbosity >= 2:
                    self.stdout.write(f"DNS {src_ip} -> {dst_ip}: {hostname}")
                return

            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
                data = bytes(pkt[Raw].load or b"")

                if (not http_strict_port) or sport == 80 or dport == 80:
                    http = _parse_http_request(data)
                    if http:
                        host, path, method, ua = http
                        url = f"http://{host}{path}"
                        ingest_event(
                            {
                                "event_type": "HTTP",
                                "asset_ip": asset_ip,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "src_port": sport,
                                "dst_port": dport,
                                "hostname": host,
                                "url": url,
                                "method": method,
                                "user_agent": ua,
                            },
                            source="sniffer",
                        )
                        stats["HTTP"] += 1
                        if verbosity >= 2:
                            self.stdout.write(f"HTTP {src_ip} -> {dst_ip}: {url}")
                        return

                if (not tls_strict_port) or sport == 443 or dport == 443:
                    sni = _parse_tls_sni(data)
                    if sni:
                        ingest_event(
                            {
                                "event_type": "TLS",
                                "asset_ip": asset_ip,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "src_port": sport,
                                "dst_port": dport,
                                "hostname": sni,
                            },
                            source="sniffer",
                        )
                        stats["TLS"] += 1
                        if verbosity >= 2:
                            self.stdout.write(f"TLS {src_ip} -> {dst_ip}: {sni}")
                        return

            stats["OTHER"] += 1
            if verbosity >= 3 and seen_packets % 50 == 0:
                self.stdout.write(f"Packets={seen_packets} DNS={stats['DNS']} HTTP={stats['HTTP']} TLS={stats['TLS']} OTHER={stats['OTHER']}")

        sniff_kwargs = {"prn": on_packet, "store": False}
        if bpf:
            sniff_kwargs["filter"] = bpf
        if iface:
            sniff_kwargs["iface"] = iface
        if pcap:
            try:
                reader = PcapReader(pcap)
            except Exception as e:
                raise CommandError(f"无法读取 pcap: {pcap}") from e
            read_n = 0
            for pkt in reader:
                on_packet(pkt)
                read_n += 1
                if count and count > 0 and read_n >= count:
                    break
            reader.close()
            self.stdout.write(f"Done. Packets={read_n} DNS={stats['DNS']} HTTP={stats['HTTP']} TLS={stats['TLS']} OTHER={stats['OTHER']}")
            return

        if count and count > 0:
            sniff_kwargs["count"] = count

        try:
            sniff(**sniff_kwargs)
        except KeyboardInterrupt:
            self.stdout.write("")
        self.stdout.write(f"Stopped. Packets={seen_packets} DNS={stats['DNS']} HTTP={stats['HTTP']} TLS={stats['TLS']} OTHER={stats['OTHER']}")


def _parse_http_request(data):
    if not data:
        return None
    if b"\r\n\r\n" not in data:
        return None
    head = data.split(b"\r\n\r\n", 1)[0]
    lines = head.split(b"\r\n")
    if not lines:
        return None
    try:
        first = lines[0].decode("iso-8859-1", errors="ignore")
    except Exception:
        return None
    parts = first.split(" ")
    if len(parts) < 2:
        return None
    method = parts[0].strip().upper()
    if method not in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}:
        return None
    path = parts[1].strip() or "/"
    host = None
    ua = None
    for raw_line in lines[1:]:
        try:
            line = raw_line.decode("iso-8859-1", errors="ignore")
        except Exception:
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        if k == "host":
            host = v
        elif k == "user-agent":
            ua = v
    if not host:
        return None
    if not path.startswith("/"):
        path = "/" + path
    return host, path, method, ua


def _parse_tls_sni(data):
    if not data or len(data) < 5:
        return None
    if data[0] != 0x16:
        return None
    rec_len = int.from_bytes(data[3:5], "big", signed=False)
    if rec_len <= 0 or 5 + rec_len > len(data):
        return None
    off = 5
    if off + 4 > len(data):
        return None
    if data[off] != 0x01:
        return None
    hs_len = int.from_bytes(data[off + 1 : off + 4], "big", signed=False)
    off += 4
    end = off + hs_len
    if end > len(data):
        return None
    if off + 2 + 32 + 1 > end:
        return None
    off += 2
    off += 32
    sid_len = data[off]
    off += 1
    if off + sid_len > end:
        return None
    off += sid_len
    if off + 2 > end:
        return None
    cs_len = int.from_bytes(data[off : off + 2], "big", signed=False)
    off += 2
    if off + cs_len > end:
        return None
    off += cs_len
    if off + 1 > end:
        return None
    cm_len = data[off]
    off += 1
    if off + cm_len > end:
        return None
    off += cm_len
    if off + 2 > end:
        return None
    ext_len = int.from_bytes(data[off : off + 2], "big", signed=False)
    off += 2
    if off + ext_len > end:
        return None
    ext_end = off + ext_len
    while off + 4 <= ext_end:
        etype = int.from_bytes(data[off : off + 2], "big", signed=False)
        elen = int.from_bytes(data[off + 2 : off + 4], "big", signed=False)
        off += 4
        if off + elen > ext_end:
            return None
        if etype == 0x0000:
            sni = _parse_sni_extension(data[off : off + elen])
            if sni:
                return sni
        off += elen
    return None


def _parse_sni_extension(buf):
    if not buf or len(buf) < 2:
        return None
    lst_len = int.from_bytes(buf[0:2], "big", signed=False)
    off = 2
    end = 2 + lst_len
    if end > len(buf):
        end = len(buf)
    while off + 3 <= end:
        name_type = buf[off]
        name_len = int.from_bytes(buf[off + 1 : off + 3], "big", signed=False)
        off += 3
        if off + name_len > end:
            return None
        if name_type == 0:
            try:
                return buf[off : off + name_len].decode("utf-8", errors="ignore")
            except Exception:
                return None
        off += name_len
    return None


def _is_private_ip(ip):
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        if addr.version == 6:
            return addr.is_private or addr.is_link_local or addr.is_loopback
        return addr.is_private or addr.is_loopback
    except Exception:
        return False
