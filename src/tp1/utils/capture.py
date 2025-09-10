from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List

from src.tp1.utils.lib import choose_interface

try:
    from scapy.all import (
        sniff,
        PacketList,
        ARP,
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        DNS,
        Raw,
    )
except Exception as exc:
    raise RuntimeError(
        "Scapy est requis pour la capture réseau. Installez-le avec `poetry add scapy`."
    ) from exc

try:
    from src.tp1.config import CAPTURE_TIMEOUT, CAPTURE_COUNT, BPF_FILTER, PROMISC  # type: ignore
except Exception:
    CAPTURE_TIMEOUT = 30
    CAPTURE_COUNT = 0
    BPF_FILTER = None
    PROMISC = True


SQLI_PATTERNS = (
    " or 1=1",
    "' or '1'='1",
    "\" or \"1\"=\"1",
    " union select ",
    "/*",
    "*/",
    "--",
    "#",
    ";--",
    " drop table ",
    " sleep(",
    " benchmark(",
    " information_schema",
    " into outfile",
    " load_file(",
    " group_concat(",
    " xp_cmdshell",
    " exec(",
    " declare @",
    " cast(",
    " convert(",
    "' or 'a'='a",
    "\" or \"a\"=\"a",
    " or 1=1--",
    " or 1=1#",
    " or '1'='1'--",
    " or '1'='1'#",
)

XSS_PATTERNS = (
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "onmouseover=",
    "onfocus=",
    "oninput=",
    "onchange=",
    "onclick=",
    "<img",
    "<iframe",
    "<svg",
    "<embed",
    "<object",
    "<link",
    "<meta",
    "<body",
    "<video",
    "<audio",
    "<base",
    "data:text/html",
    "srcdoc=",
)

LFI_RFI_PATTERNS = (
    "../../etc/passwd",
    "../../../",
    "../../../../",
    "/etc/passwd",
    "/proc/self/environ",
    "/proc/version",
    "/proc/cpuinfo",
    "c:\\windows\\win.ini",
    "c:\\boot.ini",
    "c:\\windows\\system32",
    "php://input",
    "php://filter",
    "php://expect",
    "expect://",
    "file://",
    "ftp://",
    "dict://",
    "http://",
    "https://",
)

HTTP_METHODS = (b"get ", b"post ", b"head ", b"put ", b"delete ", b"options ", b"patch ")
TLS_HELLO_PREFIX = (b"\x16\x03",)

THRESH_SYN_SCAN = 20
THRESH_SYN_FLOOD_TO_ONE_DST = 200
THRESH_BRUTEFORCE_CONN = 60
THRESH_HTTP_ENUM_PATHS = 120
THRESH_HTTP_FLOOD = 500


MAX_DETAIL_LEN = 180


class Capture:
    def __init__(self, interface: str | None = None) -> None:
        self.interface: str = interface or choose_interface()
        self.summary: str = ""
        self.packets: PacketList = PacketList()
        self.protocol_counts: Counter[str] = Counter()
        self.events: List[Dict[str, str]] = []

    def capture_trafic(self) -> None:
        """Capture le trafic réseau sur l’interface choisie."""
        self.packets = sniff(
            iface=self.interface,
            timeout=CAPTURE_TIMEOUT,
            count=CAPTURE_COUNT if CAPTURE_COUNT > 0 else 0,
            filter=BPF_FILTER,
            store=True,
            promisc=PROMISC,
        )

    def _proto_by_ports(self, pkt) -> str:
        if pkt.haslayer(TCP):
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            if 80 in (sport, dport) or 8080 in (sport, dport):
                if pkt.haslayer(Raw) and any(pkt[Raw].load[:5].lower().startswith(m) for m in HTTP_METHODS):
                    return "HTTP"
                return "TCP:80"
            if 443 in (sport, dport):
                if pkt.haslayer(Raw) and pkt[Raw].load[:2] in TLS_HELLO_PREFIX:
                    return "TLS/HTTPS"
                return "TCP:443"
            if 22 in (sport, dport):
                return "SSH"
            if 21 in (sport, dport):
                return "FTP"
            if 25 in (sport, dport) or 587 in (sport, dport):
                return "SMTP"
            if 110 in (sport, dport):
                return "POP3"
            if 143 in (sport, dport):
                return "IMAP"
            if 3389 in (sport, dport):
                return "RDP"
            if 445 in (sport, dport):
                return "SMB"
            if 3306 in (sport, dport):
                return "MySQL"
            if 5432 in (sport, dport):
                return "PostgreSQL"
            if 389 in (sport, dport):
                return "LDAP"
            if 23 in (sport, dport):
                return "Telnet"
            return "TCP"
        if pkt.haslayer(UDP):
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            if 53 in (sport, dport):
                return "DNS"
            if {67, 68}.intersection({sport, dport}):
                return "DHCP"
            if 123 in (sport, dport):
                return "NTP"
            return "UDP"
        return "OTHER"

    def _classify_protocol(self, pkt) -> str:
        if pkt.haslayer(ARP):
            return "ARP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer(DNS):
            return "DNS"
        if pkt.haslayer(IPv6):
            return "IPv6"
        if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            return self._proto_by_ports(pkt)
        if pkt.haslayer(IP):
            return "IP"
        try:
            return pkt.lastlayer().name
        except Exception:
            return "OTHER"

    def sort_network_protocols(self) -> Dict[str, List[int]]:
        """Trie et retourne les indices des paquets par protocole."""
        buckets: Dict[str, List[int]] = defaultdict(list)
        for idx, pkt in enumerate(self.packets or []):
            buckets[self._classify_protocol(pkt)].append(idx)
        return dict(buckets)

    def get_all_protocols(self) -> Dict[str, int]:
        """Retourne les protocoles capturés avec leur nombre de paquets."""
        counts: Counter[str] = Counter()
        for pkt in self.packets or []:
            counts[self._classify_protocol(pkt)] += 1
        self.protocol_counts = counts
        return dict(counts)

    def _extract_http_info(self, pkt):
        """Retourne un dict compact avec method/path/host/url pour une requête HTTP."""
        info = {"method": "", "path": "", "host": "", "url": ""}
        try:
            raw = bytes(pkt[Raw].load)
        except Exception:
            return info

        low = raw.lower()

        # méthode
        for m in (b"get ", b"post ", b"head ", b"put ", b"delete ", b"options ", b"patch "):
            if low.startswith(m):
                info["method"] = m.decode("latin-1", "ignore").strip().upper()
                break

        # première ligne: METHOD PATH HTTP/1.x
        try:
            first = raw.split(b"\r\n", 1)[0]
            parts = first.split()
            if len(parts) >= 2:
                info["path"] = parts[1].decode("latin-1", "ignore")
        except Exception:
            pass

        # host:
        try:
            headers = raw.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]
            for h in headers:
                if h.lower().startswith(b"host:"):
                    info["host"] = h.split(b":", 1)[1].strip().decode("latin-1", "ignore")
                    break
        except Exception:
            pass

        # URL
        if info["host"] and info["path"]:
            p = info["path"]
            if not p.startswith("/"):
                p = "/" + p
            try:
                dport = pkt[TCP].dport
            except Exception:
                dport = 80
            scheme = "https" if dport == 443 else "http"
            info["url"] = f"{scheme}://{info['host']}{p}"
        else:
            info["url"] = info["path"] or ""

        return info

    # detections
    def _detect_arp_spoofing(self) -> None:
        ip_to_macs: Dict[str, set] = defaultdict(set)
        for pkt in self.packets or []:
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                ip_to_macs[pkt[ARP].psrc].add(pkt[ARP].hwsrc)
        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                self.events.append(
                    {
                        "type": "ARP_SPOOFING",
                        "detail": f"Plusieurs MAC pour {ip}: {', '.join(sorted(macs))}",
                        "attacker": "inconnu",
                        "protocol": "ARP",
                    }
                )

    def _detect_port_scan(self) -> None:
        syn_map: Dict[str, set] = defaultdict(set)
        for pkt in self.packets or []:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                tcp = pkt[TCP]
                if tcp.flags & 0x02 and not (tcp.flags & 0x10):
                    syn_map[pkt[IP].src].add(tcp.dport)
        for src, ports in syn_map.items():
            if len(ports) >= THRESH_SYN_SCAN:
                self.events.append(
                    {
                        "type": "PORT_SCAN",
                        "detail": f"{len(ports)} ports ciblés",
                        "attacker": src,
                        "protocol": "TCP",
                    }
                )

    def _detect_syn_flood(self) -> None:
        to_dst: Dict[str, int] = defaultdict(int)
        for pkt in self.packets or []:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                tcp = pkt[TCP]
                if tcp.flags & 0x02 and not (tcp.flags & 0x10):
                    to_dst[f"{pkt[IP].dst}:{tcp.dport}"] += 1
        for dst, n in to_dst.items():
            if n >= THRESH_SYN_FLOOD_TO_ONE_DST:
                self.events.append(
                    {
                        "type": "SYN_FLOOD",
                        "detail": f"{n} SYN sans ACK vers {dst}",
                        "attacker": "inconnu",
                        "protocol": "TCP",
                    }
                )

    def _detect_bruteforce_services(self) -> None:
        targets = {22: "SSH", 21: "FTP", 3389: "RDP"}
        attempts_by_src_service: Dict[tuple, int] = defaultdict(int)
        for pkt in self.packets or []:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                if dport in targets and (pkt[TCP].flags & 0x02) and not (pkt[TCP].flags & 0x10):
                    attempts_by_src_service[(pkt[IP].src, dport)] += 1
        for (src, dport), n in attempts_by_src_service.items():
            if n >= THRESH_BRUTEFORCE_CONN:
                self.events.append(
                    {
                        "type": f"BRUTEFORCE_{targets[dport]}",
                        "detail": f"{n} tentatives de connexion (SYN) vers le service",
                        "attacker": src,
                        "protocol": "TCP",
                    }
                )

    def _detect_http_enum(self) -> None:
        paths_by_src: Dict[str, set] = defaultdict(set)
        for pkt in self.packets or []:
            if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
                tcp = pkt[TCP]
                if tcp.dport in (80, 8080) and pkt[Raw].load[:5].lower().startswith(HTTP_METHODS):
                    try:
                        first_line = bytes(pkt[Raw].load).split(b"\r\n", 1)[0].lower()
                        parts = first_line.split()
                        if len(parts) >= 2:
                            paths_by_src[pkt[IP].src].add(parts[1][:100])
                    except Exception:
                        continue
        for src, paths in paths_by_src.items():
            if len(paths) >= THRESH_HTTP_ENUM_PATHS:
                self.events.append(
                    {
                        "type": "HTTP_ENUMERATION",
                        "detail": f"{len(paths)} chemins différents requis",
                        "attacker": src,
                        "protocol": "HTTP",
                    }
                )

    def _detect_basic_sqli(self) -> None:
        for pkt in self.packets or []:
            if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
                tcp = pkt[TCP]
                if tcp.dport in (80, 8080, 443):
                    try:
                        payload = bytes(pkt[Raw].load).decode("latin-1", errors="ignore").lower()
                    except Exception:
                        continue
                    matched = next((pat for pat in SQLI_PATTERNS if pat in payload), None)
                    if matched:
                        info = self._extract_http_info(pkt)
                        self.events.append(
                            {
                                "type": "SQLI_PATTERN",
                                "detail": f"Motif SQLi détecté: {matched}",
                                "attacker": pkt[IP].src,
                                "protocol": "TCP/HTTP",
                                "url": info.get("url") or info.get("path") or "",
                                "method": info.get("method", ""),
                                "pattern": matched,
                            }
                        )

    def _detect_xss(self) -> None:
        for pkt in self.packets or []:
            if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
                tcp = pkt[TCP]
                if tcp.dport in (80, 8080, 443):
                    try:
                        payload = bytes(pkt[Raw].load).decode("latin-1", errors="ignore").lower()
                    except Exception:
                        continue
                    matched = next((x for x in XSS_PATTERNS if x in payload), None)
                    if matched:
                        info = self._extract_http_info(pkt)
                        self.events.append(
                            {
                                "type": "XSS_INJECTION",
                                "detail": f"Motif XSS détecté: {matched}",
                                "attacker": pkt[IP].src,
                                "protocol": "HTTP",
                                "url": info.get("url") or info.get("path") or "",
                                "method": info.get("method", ""),
                                "pattern": matched,
                            }
                        )

    def _detect_lfi_rfi(self) -> None:
        for pkt in self.packets or []:
            if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
                tcp = pkt[TCP]
                if tcp.dport in (80, 8080, 443):
                    try:
                        payload = bytes(pkt[Raw].load).decode("latin-1", errors="ignore").lower()
                    except Exception:
                        continue
                    matched = next((p for p in LFI_RFI_PATTERNS if p in payload), None)
                    if matched:
                        info = self._extract_http_info(pkt)
                        self.events.append(
                            {
                                "type": "LFI_RFI",
                                "detail": f"Tentative de LFI/RFI: {matched}",
                                "attacker": pkt[IP].src,
                                "protocol": "HTTP",
                                "url": info.get("url") or info.get("path") or "",
                                "method": info.get("method", ""),
                                "pattern": matched,
                            }
                        )

    def _detect_http_flood(self) -> None:
        reqs_by_src: Dict[str, int] = defaultdict(int)
        for pkt in self.packets or []:
            if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
                if pkt[TCP].dport in (80, 8080, 443) and pkt[Raw].load[:5].lower().startswith(HTTP_METHODS):
                    reqs_by_src[pkt[IP].src] += 1
        for src, n in reqs_by_src.items():
            if n >= THRESH_HTTP_FLOOD:
                self.events.append(
                    {
                        "type": "HTTP_FLOOD",
                        "detail": f"{n} requêtes HTTP envoyées",
                        "attacker": src,
                        "protocol": "HTTP",
                    }
                )

    def analyse(self, protocols: str | None = None) -> None:
        """Analyse les paquets capturés et détecte certains comportements suspects."""
        self.get_all_protocols()
        self.sort_network_protocols()
        self._detect_arp_spoofing()
        self._detect_port_scan()
        self._detect_syn_flood()
        self._detect_bruteforce_services()
        self._detect_http_enum()
        self._detect_basic_sqli()
        self._detect_xss()
        self._detect_lfi_rfi()
        self._detect_http_flood()
        self.summary = self.gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def gen_summary(self) -> str:
        """Génère un résumé avec statistiques et anomalies détectées."""
        lines: List[str] = []
        total = sum(self.protocol_counts.values())
        lines.append(f"Interface : {self.interface}")
        lines.append(f"Paquets capturés : {total}")
        lines.append("")
        lines.append("Protocoles :")
        if total:
            for proto, count in sorted(self.protocol_counts.items(), key=lambda x: (-x[1], x[0])):
                pct = (count / total) * 100 if total else 0.0
                lines.append(f"  - {proto:<12} : {count:>6}  ({pct:5.1f}%)")
        else:
            lines.append("  - Aucun paquet capturé")

        lines.append("")
        if not self.events:
            lines.append("Analyse : Aucun trafic illégitime détecté. ✅")
        else:
            lines.append("Analyse : Événements suspects détectés ❗")
            for ev in self.events:
                extra = ""
                if ev.get("url"):
                    extra += f" | url={ev['url']}"
                if ev.get("method"):
                    extra += f" | method={ev['method']}"
                lines.append(
                    f"  - [{ev['type']}] proto={ev['protocol']} | attaquant={ev['attacker']} | {ev['detail']}{extra}"
                )

        return "\n".join(lines)
