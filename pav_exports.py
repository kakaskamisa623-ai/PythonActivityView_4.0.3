from __future__ import annotations

"""Optional Unicode PDF report exporter for PAV.

HTML/JSON/CSV remain the dependency-free exports. PDF generation uses ReportLab
and a locally installed Unicode TrueType font; no font is bundled or shipped.
"""

import os
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape


def _find_unicode_font() -> Path | None:
    candidates: list[Path] = []
    windir = os.environ.get("WINDIR")
    if windir:
        candidates.extend([
            Path(windir) / "Fonts" / "arial.ttf",
            Path(windir) / "Fonts" / "segoeui.ttf",
            Path(windir) / "Fonts" / "tahoma.ttf",
        ])
    candidates.extend([
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf"),
        Path("/Library/Fonts/Arial Unicode.ttf"),
        Path("/System/Library/Fonts/Supplemental/Arial.ttf"),
    ])
    return next((p for p in candidates if p.is_file()), None)


def build_pdf_report(report: dict[str, Any], output_path: str | os.PathLike[str], *,
                     font_path: str | os.PathLike[str] | None = None,
                     max_events: int = 2500) -> dict[str, Any]:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    except ImportError as exc:
        raise RuntimeError("PDF export needs ReportLab. Install: python -m pip install reportlab") from exc

    selected_font = Path(font_path) if font_path else _find_unicode_font()
    if not selected_font or not selected_font.is_file():
        raise RuntimeError("A Unicode TrueType font was not found. Install Arial/Segoe UI/DejaVu Sans or pass font_path.")
    pdfmetrics.registerFont(TTFont("PAVUnicode", str(selected_font)))

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="PAVTitle", parent=styles["Title"], fontName="PAVUnicode", fontSize=18, leading=22, alignment=TA_LEFT, textColor=colors.HexColor("#243447")))
    styles.add(ParagraphStyle(name="PAVBody", parent=styles["BodyText"], fontName="PAVUnicode", fontSize=8.5, leading=11, spaceAfter=4))
    styles.add(ParagraphStyle(name="PAVSmall", parent=styles["BodyText"], fontName="PAVUnicode", fontSize=7, leading=9))
    styles.add(ParagraphStyle(name="PAVHeading", parent=styles["Heading2"], fontName="PAVUnicode", fontSize=12, leading=15, spaceBefore=10, spaceAfter=5))

    case = report.get("case_context", {}).get("case", {}) if isinstance(report.get("case_context"), dict) else {}
    risk = report.get("analysis_quality", {}).get("risk_assessment", {}) if isinstance(report.get("analysis_quality"), dict) else {}
    events = list(report.get("events", []))
    if report.get("system_trace_analysis"):
        events.extend(report["system_trace_analysis"].get("events", []))
    if not events:
        events = list(report.get("forensic_events", []))

    story = [Paragraph(escape(str(report.get("application", "Python Activity View"))) + " " + escape(str(report.get("version", ""))), styles["PAVTitle"]),
             Paragraph("Generated: " + escape(str(report.get("generated_local") or report.get("scan_info", {}).get("generated_local", "—"))), styles["PAVBody"]),
             Paragraph("Case: " + escape(str(case.get("name", "—"))), styles["PAVBody"]),
             Paragraph("Assessment: " + escape(str(risk.get("label", "Insufficient data"))) + " · heuristic score " + escape(str(risk.get("score", "—"))), styles["PAVBody"]),
             Paragraph("This assessment is an explainable heuristic, not a probability or a verdict. Missing sources do not prove that an activity did not occur.", styles["PAVBody"])]

    if case.get("notes"):
        story.extend([Paragraph("Case notes", styles["PAVHeading"]), Paragraph(escape(str(case["notes"])).replace("\n", "<br/>"), styles["PAVBody"])])
    reasons = risk.get("reasons", []) if isinstance(risk, dict) else []
    if reasons:
        story.append(Paragraph("Assessment reasons", styles["PAVHeading"]))
        for item in reasons[:100]:
            story.append(Paragraph("• " + escape(str(item.get("evidence", ""))) + " — " + escape(str(item.get("strength", ""))), styles["PAVBody"]))
    evidence = case.get("evidence", []) if isinstance(case, dict) else []
    if evidence:
        story.append(Paragraph("Case evidence register", styles["PAVHeading"]))
        data = [["File", "Size", "SHA-256", "Included"]]
        for item in evidence:
            data.append([Paragraph(escape(str(item.get("name", ""))), styles["PAVSmall"]),
                         str(item.get("size_bytes", "")),
                         Paragraph(escape(str(item.get("sha256", ""))), styles["PAVSmall"]),
                         "Yes" if item.get("included", True) else "No"])
        t = Table(data, colWidths=[48 * mm, 18 * mm, 90 * mm, 18 * mm], repeatRows=1)
        t.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, -1), "PAVUnicode"), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf3")), ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#bdc5cf")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 4)]))
        story.append(t)

    story.append(Paragraph(f"Events ({len(events)} total; up to {max_events} included)", styles["PAVHeading"]))
    data = [["Timestamp", "Type", "Description", "Command / content", "Source"]]
    for item in events[:max_events]:
        data.append([
            Paragraph(escape(str(item.get("timestamp", ""))), styles["PAVSmall"]),
            Paragraph(escape(str(item.get("kind", ""))), styles["PAVSmall"]),
            Paragraph(escape(str(item.get("description", ""))), styles["PAVSmall"]),
            Paragraph(escape(str(item.get("command", ""))), styles["PAVSmall"]),
            Paragraph(escape(str(item.get("source", ""))), styles["PAVSmall"]),
        ])
    event_table = Table(data, colWidths=[25 * mm, 28 * mm, 58 * mm, 63 * mm, 35 * mm], repeatRows=1)
    event_table.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, -1), "PAVUnicode"), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf3")), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c6cbd1")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 3)]))
    story.append(event_table)

    warnings = list(report.get("warnings", [])) + list(report.get("errors", []))
    if warnings:
        story.append(Paragraph("Warnings and limitations", styles["PAVHeading"]))
        for warning in warnings[:150]:
            story.append(Paragraph("• " + escape(str(warning)), styles["PAVSmall"]))
    if len(events) > max_events:
        story.append(Paragraph(f"The PDF contains the first {max_events} events. Use JSON/CSV for the complete dataset.", styles["PAVBody"]))

    def page_footer(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("PAVUnicode", 7)
        canvas.setFillColor(colors.HexColor("#687385"))
        canvas.drawString(14 * mm, 9 * mm, "Python Activity View · local forensic review")
        canvas.drawRightString(landscape(A4)[0] - 14 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(output), pagesize=landscape(A4), rightMargin=14 * mm, leftMargin=14 * mm, topMargin=14 * mm, bottomMargin=16 * mm, title="Python Activity View report", author="Python Activity View")
    doc.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
    return {"path": str(output), "size_bytes": output.stat().st_size, "font": str(selected_font), "events_total": len(events), "events_included": min(len(events), max_events)}
