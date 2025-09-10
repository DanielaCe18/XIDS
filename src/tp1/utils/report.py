from __future__ import annotations

import os
from typing import List, Dict

import pygal
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from svglib.svglib import svg2rlg  # pour insérer un SVG dans un PDF
from reportlab.graphics import renderPDF


class Report:
    def __init__(self, capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename if filename.endswith(".pdf") else f"{filename}.pdf"
        self.title = "RAPPORT DE SURVEILLANCE RÉSEAU"
        self.summary = summary
        self.array_data: List[List[str]] = []
        self.svg_path = os.path.splitext(self.filename)[0] + "_protocols.svg"

    # Générateurs de contenu
    def _make_table_data(self) -> List[List[str]]:
        counts: Dict[str, int] = dict(self.capture.protocol_counts or {})
        total = sum(counts.values()) or 1
        data: List[List[str]] = [["Protocole", "Paquets", "%"]]
        for proto, n in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
            pct = f"{(n / total) * 100:5.1f}%"
            data.append([proto, str(n), pct])
        return data

    def _make_pygal_chart(self, svg_path: str) -> None:
        counts: Dict[str, int] = dict(self.capture.protocol_counts or {})
        chart = pygal.Bar(x_label_rotation=30, show_legend=False, print_values=False)
        chart.title = "Répartition des protocoles capturés"
        labels = []
        values = []
        for proto, n in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
            labels.append(proto)
            values.append(n)
        chart.x_labels = labels or ["Aucune donnée"]
        chart.add("Paquets", values or [0])
        chart.render_to_file(svg_path)

    # API publique (compat avec ton main.py)
    def generate(self, param: str) -> None:
        """
        'graph' -> génère le graphique SVG
        'array' -> prépare les données du tableau
        """
        if param == "graph":
            self._make_pygal_chart(self.svg_path)
        elif param == "array":
            self.array_data = self._make_table_data()

    # Construction du PDF
    def _build_pdf(self) -> None:
        styles = getSampleStyleSheet()
        h1 = styles["Heading1"]
        body = styles["BodyText"]
        mono = ParagraphStyle("mono", parent=body, fontName="Courier", leading=12)

        doc = SimpleDocTemplate(self.filename, pagesize=A4,
                                rightMargin=2*cm, leftMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        elements: List = []

        # Titre
        elements.append(Paragraph(self.title, h1))
        elements.append(Spacer(1, 0.5 * cm))

        # Résumé (monospace, lignes conservées)
        summary_html = "<br/>".join(self.summary.splitlines())
        elements.append(Paragraph("<b>Résumé</b>", styles["Heading2"]))
        elements.append(Spacer(1, 0.2 * cm))
        elements.append(Paragraph(summary_html, mono))
        elements.append(Spacer(1, 0.6 * cm))

        # Tableau
        if self.array_data:
            elements.append(Paragraph("<b>Tableau des protocoles</b>", styles["Heading2"]))
            elements.append(Spacer(1, 0.2 * cm))
            table = Table(self.array_data, hAlign="LEFT", colWidths=[6 * cm, 3 * cm, 3 * cm])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                        ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    ]
                )
            )
            elements.append(table)
            elements.append(Spacer(1, 0.6 * cm))

        # Graphique (SVG) 
        if os.path.exists(self.svg_path):
            elements.append(Paragraph("<b>Graphique des protocoles</b>", styles["Heading2"]))
            elements.append(Spacer(1, 0.2 * cm))
            drawing = svg2rlg(self.svg_path)
            # Mise à l’échelle pour tenir dans la page (largeur ≈ 16 cm)
            scale = (16 * cm) / max(drawing.minWidth(), 1)
            drawing.width *= scale
            drawing.height *= scale
            drawing.scale(scale, scale)
            # On insère le Drawing directement comme Flowable
            elements.append(drawing)
            elements.append(Spacer(1, 0.2 * cm))

        # Événements
        events = getattr(self.capture, "events", [])
        elements.append(Paragraph("<b>Événements détectés</b>", styles["Heading2"]))
        elements.append(Spacer(1, 0.2 * cm))
        if events:
            for ev in events:
                extras = []
                if ev.get("url"):
                    extras.append(f"url={ev['url']}")
                if ev.get("method"):
                    extras.append(f"method={ev['method']}")
                extra_txt = (" | " + " | ".join(extras)) if extras else ""
                line = (f"[{ev.get('type','?')}] "
                        f"proto={ev.get('protocol','?')} | "
                        f"attaquant={ev.get('attacker','?')} | "
                        f"{ev.get('detail','')}{extra_txt}")
                elements.append(Paragraph(line, body))
        else:
            elements.append(Paragraph("Aucun événement suspect détecté.", body))

        doc.build(elements)

    def concat_report(self) -> str:
        """
        Version texte fallback (rarement utilisée désormais).
        """
        parts: List[str] = [
            self.title,
            "",
            "=== Résumé ===",
            self.summary.strip(),
        ]
        return "\n".join(parts)

    def save(self, filename: str) -> None:
        """
        Construit le PDF final (et laisse les fichiers SVG à côté).
        """
        self._build_pdf()
