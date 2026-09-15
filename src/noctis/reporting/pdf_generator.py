"""PDF report via ReportLab (not WeasyPrint -- WeasyPrint needs a native GTK3
runtime that isn't available on a plain Windows install, which breaks the
plan's own cross-platform requirement; ReportLab is a pure-Python wheel with
no native dependency). Dark cyberpunk theme matching Noctis branding: dark
background, red/cyan accents. Structure: cover page, executive summary,
scope & methodology, findings table sorted by severity, one detail section
per finding (description/CVSS/OWASP/ATT&CK/PoC/evidence/remediation), and an
appendix with the raw request/response for every finding.
"""
from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)

from noctis.reporting.report_data import SEVERITY_ORDER, ReportData

BG = colors.HexColor("#0b0e14")
PANEL = colors.HexColor("#131826")
TEXT = colors.HexColor("#e6e6e6")
MUTED = colors.HexColor("#8a93a6")
RED = colors.HexColor("#ff3b5c")
CYAN = colors.HexColor("#00e5ff")
AMBER = colors.HexColor("#ffb020")
GREEN = colors.HexColor("#3ddc84")

SEVERITY_COLOR = {"Critical": RED, "High": RED, "Medium": AMBER, "Low": GREEN, "Info": MUTED}

STYLES = {
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=28, leading=34, textColor=RED, spaceAfter=16, alignment=1),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=13, leading=16, textColor=CYAN, spaceAfter=6, alignment=1),
    "meta": ParagraphStyle("meta", fontName="Helvetica", fontSize=10, textColor=MUTED, alignment=1),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=18, textColor=CYAN, spaceBefore=18, spaceAfter=10),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=13, textColor=RED, spaceBefore=14, spaceAfter=6),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=10, textColor=TEXT, leading=14, spaceAfter=6),
    "label": ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=9, textColor=MUTED),
    "code": ParagraphStyle("code", fontName="Courier", fontSize=8, textColor=TEXT, backColor=PANEL, leading=11),
}


def generate(data: ReportData, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.pdf"

    doc = BaseDocTemplate(str(path), pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm, leftMargin=2 * cm, rightMargin=2 * cm)
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="body")
    doc.addPageTemplates([PageTemplate(id="dark", frames=[frame], onPage=_draw_background)])

    story: list = []
    story += _cover_page(data)
    story.append(PageBreak())
    story += _executive_summary(data)
    story += _scope_and_methodology(data)
    if data.findings:
        story += _findings_table(data)
        story.append(PageBreak())
        story += _detailed_findings(data)
        story.append(PageBreak())
        story += _appendix(data)
    else:
        story.append(Paragraph("No findings were confirmed during this scan.", STYLES["body"]))

    doc.build(story)
    return path


def _draw_background(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFillColor(BG)
    canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)
    canvas.restoreState()


def _cover_page(data: ReportData) -> list:
    return [
        Spacer(1, 6 * cm),
        Paragraph("NOCTIS", STYLES["title"]),
        Paragraph("Security Assessment Report", STYLES["subtitle"]),
        Spacer(1, 1.5 * cm),
        Paragraph(data.target, ParagraphStyle("target", parent=STYLES["body"], fontSize=14, textColor=TEXT, alignment=1)),
        Spacer(1, 0.5 * cm),
        Paragraph(f"Generated {data.generated_at}", STYLES["meta"]),
        Paragraph(f"Workspace {data.workspace_id}", STYLES["meta"]),
    ]


def _executive_summary(data: ReportData) -> list:
    story = [Paragraph("Executive Summary", STYLES["h1"])]
    counts = data.severity_counts
    rows = [["Severity", "Count"]] + [[s, str(counts[s])] for s in SEVERITY_ORDER if counts.get(s)]
    if len(rows) > 1:
        table = Table(rows, colWidths=[6 * cm, 3 * cm])
        table.setStyle(_table_style(header_color=CYAN))
        story.append(table)
        story.append(Spacer(1, 0.4 * cm))

    story.append(
        Paragraph(
            f"{len(data.findings)} finding(s) confirmed via independent replay out of "
            f"{data.total_attempted} exploitation attempt(s); {data.discarded_count} candidate(s) "
            f"did not reproduce and were discarded rather than reported.",
            STYLES["body"],
        )
    )
    return story


def _scope_and_methodology(data: ReportData) -> list:
    story = [Paragraph("Scope & Methodology", STYLES["h1"])]
    story.append(Paragraph(f"<b>Include patterns:</b> {', '.join(data.scope_include) or '(all in-scope)'}", STYLES["body"]))
    story.append(Paragraph(f"<b>Exclude patterns:</b> {', '.join(data.scope_exclude) or '(none)'}", STYLES["body"]))
    story.append(Paragraph(f"<b>Stages run:</b> {' -> '.join(data.stages_run)}", STYLES["body"]))
    return story


def _findings_table(data: ReportData) -> list:
    story = [Paragraph("Findings", STYLES["h1"])]
    rows = [["Severity", "CVSS", "Type", "OWASP", "Finding ID"]]
    for f in data.findings:
        rows.append([f.severity, f"{f.cvss_score:.1f}", f.agent_type, f.owasp_category, f.finding_id])

    table = Table(rows, colWidths=[2.3 * cm, 1.6 * cm, 2.3 * cm, 5.5 * cm, 4 * cm], repeatRows=1)
    style = _table_style(header_color=CYAN)
    for i, f in enumerate(data.findings, start=1):
        style.add("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLOR.get(f.severity, TEXT))
        style.add("FONTNAME", (0, i), (0, i), "Helvetica-Bold")
    table.setStyle(style)
    story.append(table)
    return story


def _detailed_findings(data: ReportData) -> list:
    story = [Paragraph("Detailed Findings", STYLES["h1"])]
    for f in data.findings:
        color = SEVERITY_COLOR.get(f.severity, TEXT)
        heading_style = ParagraphStyle("finding_heading", parent=STYLES["h2"], textColor=color)
        story.append(Paragraph(f"[{f.severity}] {f.agent_type} -- {f.finding_id}", heading_style))
        story.append(Paragraph(f"<b>CVSS:</b> {f.cvss_score:.1f} ({f.cvss_vector})", STYLES["body"]))
        story.append(Paragraph(f"<b>OWASP:</b> {f.owasp_category}", STYLES["body"]))
        story.append(Paragraph(f"<b>MITRE ATT&amp;CK:</b> {f.attack_tactic} / {f.attack_technique}", STYLES["body"]))
        story.append(Paragraph(f"<b>Node:</b> {_escape(f.node_id)}", STYLES["body"]))
        story.append(Paragraph(f"<b>Evidence:</b> {_escape(f.evidence)}", STYLES["body"]))
        story.append(Paragraph(f"<b>Payload:</b> {_escape(f.payload)}", STYLES["body"]))

        if f.screenshot_path and Path(f.screenshot_path).exists():
            story.append(_scaled_image(f.screenshot_path, max_width=14 * cm))
            story.append(Spacer(1, 0.2 * cm))

        story.append(Paragraph(f"<b>Remediation:</b> {_escape(f.remediation)}", STYLES["body"]))
        story.append(Spacer(1, 0.4 * cm))
    return story


def _appendix(data: ReportData) -> list:
    story = [Paragraph("Appendix: Raw Requests", STYLES["h1"])]
    for f in data.findings:
        story.append(Paragraph(f"{f.finding_id}", STYLES["h2"]))
        story.append(Preformatted(_truncate(f.request, 2000), STYLES["code"]))
        story.append(Spacer(1, 0.1 * cm))
        story.append(Preformatted(_truncate(f.response, 2000), STYLES["code"]))
        story.append(Spacer(1, 0.4 * cm))
    return story


def _table_style(header_color) -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), PANEL),
            ("TEXTCOLOR", (0, 0), (-1, 0), header_color),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 1), (-1, -1), TEXT),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, MUTED),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
    )


def _scaled_image(path: str, max_width: float) -> Image:
    reader = ImageReader(path)
    width, height = reader.getSize()
    scale = max_width / width
    return Image(path, width=max_width, height=height * scale)


def _escape(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _truncate(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "\n... (truncated)"
