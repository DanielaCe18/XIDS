import os

from scapy.all import PacketList
from src.tp1.utils.capture import Capture
from src.tp1.utils.report import Report


def test_report_svg_and_pdf_generation(tmp_path, monkeypatch):
    # Capture avec quelques stats factices
    cap = Capture()
    cap.packets = PacketList()
    # Simule des stats: on peut appeler get_all_protocols après avoir mis des attributs privés
    # Ici on "triche" en assignant directement
    cap.protocol_counts.update({"HTTP": 5, "DNS": 3, "ARP": 2})
    cap.summary = "Résumé de test.\nTout va bien."

    pdf_path = tmp_path / "report_test.pdf"
    r = Report(cap, str(pdf_path), cap.summary)

    # Génère SVG et tableau, puis PDF
    r.generate("graph")
    r.generate("array")
    r.save(str(pdf_path))

    # Fichiers attendus
    svg_path = str(pdf_path).replace(".pdf", "_protocols.svg")
    assert os.path.exists(svg_path), "Le SVG Pygal n'a pas été créé"
    assert os.path.getsize(svg_path) > 0

    assert os.path.exists(pdf_path), "Le PDF final n'a pas été créé"
    assert os.path.getsize(pdf_path) > 0
