import os
import time

import pytest
from scapy.all import IP, TCP, UDP, ARP, DNS, DNSQR, Raw, PacketList

from src.tp1.utils.capture import Capture
import src.tp1.utils.capture as capture_mod


def _http_req(src="10.0.0.1", dst="10.0.0.2", path="/", method=b"GET "):
    payload = method + path.encode() + b" HTTP/1.1\r\nHost: test\r\n\r\n"
    return IP(src=src, dst=dst) / TCP(sport=12345, dport=80) / Raw(load=payload)


def _https_payload(src="10.0.0.1", dst="10.0.0.2"):
    return IP(src=src, dst=dst) / TCP(sport=12345, dport=443) / Raw(load=b"\x16\x03\x01\x00\x2e")


def _syn_pkt(src="10.0.0.9", dst="10.0.0.2", dport=22):
    # flags="S" -> SYN
    return IP(src=src, dst=dst) / TCP(sport=50000, dport=dport, flags="S")


def _arp_reply(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff"):
    # op=2 (reply), psrc = owner IP, hwsrc = MAC
    return ARP(op=2, psrc=ip, hwsrc=mac, pdst="192.168.1.1", hwdst="11:22:33:44:55:66")


def _dns_query(src="10.0.0.3", qname="example.com"):
    return IP(src=src, dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(qr=0, qd=DNSQR(qname=qname))


@pytest.fixture
def cap(monkeypatch):
    c = Capture()
    c.packets = PacketList()
    # on abaisse les seuils pour tests rapides
    monkeypatch.setattr(capture_mod, "THRESH_SYN_SCAN", 5, raising=True)
    monkeypatch.setattr(capture_mod, "THRESH_BRUTEFORCE_CONN", 5, raising=True)
    monkeypatch.setattr(capture_mod, "THRESH_HTTP_ENUM_PATHS", 10, raising=True)
    monkeypatch.setattr(capture_mod, "THRESH_HTTP_FLOOD", 10, raising=True)
    return c


def test_protocol_classification_and_counts(cap):
    # ARP reply
    cap.packets.append(_arp_reply())
    # DNS query
    cap.packets.append(_dns_query())
    # HTTP
    cap.packets.append(_http_req(path="/index"))
    # HTTPS
    cap.packets.append(_https_payload())
    # SSH SYN
    cap.packets.append(_syn_pkt(dport=22))
    # NTP (UDP:123)
    cap.packets.append(IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=123, dport=123))

    counts = cap.get_all_protocols()
    assert counts["ARP"] == 1
    assert counts["DNS"] == 1
    # HTTP et TLS/HTTPS détectés par ports/contenu
    assert counts["HTTP"] == 1 or counts.get("TCP:80", 0) == 1
    assert counts.get("TLS/HTTPS", 0) + counts.get("TCP:443", 0) == 1
    assert counts["SSH"] == 1
    assert counts["NTP"] == 1


def test_detect_arp_spoofing(cap):
    # Deux réponses ARP différentes pour la même IP
    cap.packets.extend([_arp_reply("10.0.0.10", "aa:aa:aa:aa:aa:aa"),
                        _arp_reply("10.0.0.10", "bb:bb:bb:bb:bb:bb")])
    cap.analyse(None)
    types = {e["type"] for e in cap.events}
    assert "ARP_SPOOFING" in types


def test_detect_port_scan(cap):
    # Même source scanne 6 ports différents => dépasse THRESH_SYN_SCAN=5 (monkeypatch)
    cap.packets.extend([_syn_pkt(dport=p) for p in (21, 22, 23, 80, 443, 3389)])
    cap.analyse(None)
    types = {e["type"] for e in cap.events}
    assert "PORT_SCAN" in types


def test_detect_bruteforce_ssh(cap):
    # Même source tente 6 connexions SYN vers SSH => dépasse THRESH_BRUTEFORCE_CONN=5
    cap.packets.extend([_syn_pkt(dport=22) for _ in range(6)])
    cap.analyse(None)
    labels = {(e["type"], e["protocol"]) for e in cap.events}
    assert ("BRUTEFORCE_SSH", "TCP") in labels


def test_detect_xss_lfi_httpflood(cap, monkeypatch):
    # XSS
    cap.packets.append(
        IP(src="10.0.0.5", dst="10.0.0.2") / TCP(sport=12345, dport=80) /
        Raw(load=b"GET /?q=<script>alert(1)</script> HTTP/1.1\r\n\r\n")
    )
    # LFI/RFI
    cap.packets.append(
        IP(src="10.0.0.6", dst="10.0.0.2") / TCP(sport=12345, dport=80) /
        Raw(load=b"GET /?file=../../etc/passwd HTTP/1.1\r\n\r\n")
    )

    # HTTP flood: 12 requêtes GET depuis la même IP (seuil=10)
    flood_src = "10.0.0.99"
    for i in range(12):
        cap.packets.append(_http_req(src=flood_src, path=f"/p{i}"))

    cap.analyse(None)
    types = {e["type"] for e in cap.events}
    assert "XSS_INJECTION" in types
    assert "LFI_RFI" in types
    assert "HTTP_FLOOD" in types
