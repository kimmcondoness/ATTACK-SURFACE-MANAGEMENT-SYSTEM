"""PDF layout for the per-target attack surface report.

Pure rendering: takes a plain dict (see build_pdf) and draws it, so it has no
database access and can be previewed with hand-made data. Palette follows
DESIGN.md: ink + paper, one green accent, and the four-step severity scale.
"""

from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    NextPageTemplate,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

INK = colors.HexColor("#0c1210")
PAPER = colors.HexColor("#f4f1e9")
PAPER_LINE = colors.HexColor("#d9d3c1")
TEXT = colors.HexColor("#1c1f1a")
MUTED = colors.HexColor("#5c5b50")
ACCENT = colors.HexColor("#3fae6a")
ACCENT_DARK = colors.HexColor("#2c8752")

# bar/strip colour, tinted cell background, readable text colour (all >= 4.5:1 on the tint)
SEVERITY = {
    "critical": (colors.HexColor("#b3261e"), colors.HexColor("#fbeae7"), colors.HexColor("#8f1c15")),
    "high": (colors.HexColor("#b5651d"), colors.HexColor("#fbeee2"), colors.HexColor("#844710")),
    "medium": (colors.HexColor("#a68b12"), colors.HexColor("#faf3de"), colors.HexColor("#6e5c08")),
    "low": (colors.HexColor("#4c6b8a"), colors.HexColor("#e9eff5"), colors.HexColor("#344c66")),
}
SEVERITY_ORDER = ("critical", "high", "medium", "low")

PAGE_W, PAGE_H = A4
MARGIN = 1.9 * cm
CONTENT_W = PAGE_W - 2 * MARGIN
BAND_H = 5.6 * cm

_body = ParagraphStyle("body", fontName="Helvetica", fontSize=9.5, leading=14, textColor=TEXT, alignment=TA_LEFT)
_small = ParagraphStyle("small", parent=_body, fontSize=8.5, leading=12, textColor=MUTED)
_h1 = ParagraphStyle("h1", parent=_body, fontName="Helvetica-Bold", fontSize=13.5, leading=17, textColor=INK, spaceBefore=16, spaceAfter=4)
_finding_title = ParagraphStyle("ft", parent=_body, fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=INK)
_label = ParagraphStyle("label", parent=_body, fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=ACCENT_DARK, spaceBefore=6)
_step = ParagraphStyle("step", parent=_body, fontSize=9, leading=13, leftIndent=14, firstLineIndent=-14, spaceAfter=2)
_cell = ParagraphStyle("cell", parent=_body, fontSize=8.5, leading=11.5)
_cell_mono = ParagraphStyle("cellmono", parent=_cell, fontName="Courier", fontSize=8.3)
_head_cell = ParagraphStyle("headcell", parent=_cell, fontName="Helvetica-Bold", fontSize=7.5, textColor=colors.white)
_tile_num = ParagraphStyle("tilenum", parent=_body, fontName="Courier-Bold", fontSize=22, leading=26, textColor=INK)
_tile_label = ParagraphStyle("tilelabel", parent=_body, fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=MUTED)


def _esc(value):
    return escape(str(value if value is not None else ""))


def _sev(severity):
    return SEVERITY.get((severity or "").lower(), SEVERITY["medium"])


# ---------------------------------------------------------------- page chrome


class _NumberedCanvas(pdfcanvas.Canvas):
    """Two-pass canvas so the footer can say "Page 2 of 5"."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            self._footer(total)
            super().showPage()
        super().save()

    def _footer(self, total):
        self.setStrokeColor(PAPER_LINE)
        self.setLineWidth(0.6)
        self.line(MARGIN, 1.5 * cm, PAGE_W - MARGIN, 1.5 * cm)
        self.setFont("Helvetica", 7.5)
        self.setFillColor(MUTED)
        self.drawString(MARGIN, 1.0 * cm, "Confidential. Prepared for authorized personnel only.")
        self.drawRightString(PAGE_W - MARGIN, 1.0 * cm, f"Page {self._pageNumber} of {total}")


def _cover_band(data):
    def draw(canv, doc):
        canv.saveState()
        canv.setFillColor(INK)
        canv.rect(0, PAGE_H - BAND_H, PAGE_W, BAND_H, stroke=0, fill=1)
        canv.setFillColor(ACCENT)
        canv.rect(0, PAGE_H - BAND_H - 0.14 * cm, PAGE_W, 0.14 * cm, stroke=0, fill=1)

        canv.setFillColor(ACCENT)
        canv.circle(MARGIN + 0.16 * cm, PAGE_H - 1.55 * cm, 0.16 * cm, stroke=0, fill=1)
        canv.setFillColor(colors.HexColor("#c7d6cd"))
        canv.setFont("Courier-Bold", 9)
        canv.drawString(MARGIN + 0.6 * cm, PAGE_H - 1.66 * cm, "ATTACK SURFACE MANAGEMENT")

        canv.setFillColor(colors.white)
        canv.setFont("Helvetica-Bold", 25)
        canv.drawString(MARGIN, PAGE_H - 3.05 * cm, "Attack Surface Report")
        canv.setFillColor(ACCENT)
        canv.setFont("Courier-Bold", 15)
        canv.drawString(MARGIN, PAGE_H - 3.85 * cm, data["domain"])
        canv.setFillColor(colors.HexColor("#c7d6cd"))
        canv.setFont("Helvetica", 8.5)
        canv.drawString(
            MARGIN,
            PAGE_H - 4.65 * cm,
            f"Generated {data['generated_at']:%Y-%m-%d %H:%M} UTC" + (f"   |   Prepared by {data['generated_by']}" if data.get("generated_by") else ""),
        )
        canv.restoreState()

    return draw


def _later_header(data):
    def draw(canv, doc):
        canv.saveState()
        canv.setFillColor(ACCENT)
        canv.circle(MARGIN + 0.1 * cm, PAGE_H - 1.15 * cm, 0.1 * cm, stroke=0, fill=1)
        canv.setFillColor(MUTED)
        canv.setFont("Courier-Bold", 7.5)
        canv.drawString(MARGIN + 0.4 * cm, PAGE_H - 1.2 * cm, "ATTACK SURFACE MANAGEMENT")
        canv.drawRightString(PAGE_W - MARGIN, PAGE_H - 1.2 * cm, data["domain"])
        canv.setStrokeColor(PAPER_LINE)
        canv.setLineWidth(0.6)
        canv.line(MARGIN, PAGE_H - 1.5 * cm, PAGE_W - MARGIN, PAGE_H - 1.5 * cm)
        canv.restoreState()

    return draw


# ------------------------------------------------------------------ sections


def _section(title):
    heading = Paragraph(title, _h1)
    rule = HRFlowable(width="100%", thickness=1.2, color=ACCENT, spaceAfter=8)
    heading.keepWithNext = 1
    rule.keepWithNext = 1
    return [heading, rule]


def _trim(text, limit=320):
    """Shorten a stored description at a sentence (or word) boundary rather than mid-word."""
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    cut = text[:limit]
    sentence_end = max(cut.rfind(". "), cut.rfind("? "), cut.rfind("! "))
    if sentence_end > limit * 0.5:
        return cut[: sentence_end + 1]
    return cut.rsplit(" ", 1)[0] + "..."


def _stat_tiles(data):
    tiles = [
        (len(data["assets"]), "ASSETS"),
        (data["port_total"], "OPEN PORTS"),
        (len(data["findings"]), "FINDINGS"),
        (data["risk_score"], "RISK SCORE"),
    ]
    # each tile is a number stacked over its label, inside one cell
    cells = [[Paragraph(str(n), _tile_num), Paragraph(label, _tile_label)] for n, label in tiles]
    table = Table([cells], colWidths=[CONTENT_W / 4] * 4)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PAPER),
                ("BOX", (0, 0), (-1, -1), 0.6, PAPER_LINE),
                ("LINEAFTER", (0, 0), (-2, -1), 0.6, PAPER_LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 11),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 13),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def _severity_bars(counts):
    row_h = 0.72 * cm
    label_w = 2.4 * cm
    count_w = 1.4 * cm
    track_w = CONTENT_W - label_w - count_w
    drawing = Drawing(CONTENT_W, row_h * len(SEVERITY_ORDER))
    biggest = max(counts.values()) if counts and max(counts.values()) else 0

    for i, level in enumerate(SEVERITY_ORDER):
        y = row_h * (len(SEVERITY_ORDER) - 1 - i)
        n = counts.get(level, 0)
        bar_color, tint, _ = SEVERITY[level]
        drawing.add(String(0, y + 0.22 * cm, level.capitalize(), fontName="Helvetica-Bold", fontSize=8.5, fillColor=TEXT))
        drawing.add(Rect(label_w, y + 0.12 * cm, track_w, 0.36 * cm, fillColor=PAPER, strokeColor=None))
        if n and biggest:
            drawing.add(Rect(label_w, y + 0.12 * cm, max(track_w * n / biggest, 0.12 * cm), 0.36 * cm, fillColor=bar_color, strokeColor=None))
        drawing.add(String(label_w + track_w + 0.3 * cm, y + 0.2 * cm, str(n), fontName="Courier-Bold", fontSize=10, fillColor=TEXT))
    return drawing


def _executive_summary(data):
    findings = data["findings"]
    domain = _esc(data["domain"])
    n_assets = len(data["assets"])
    if not findings:
        return (
            f"This report covers {n_assets} asset{'s' if n_assets != 1 else ''} on <b>{domain}</b>. "
            "No findings were recorded."
        )
    counts = data["counts"]
    parts = [f"{counts.get(level, 0)} {level}" for level in SEVERITY_ORDER]
    text = (
        f"This report covers {n_assets} asset{'s' if n_assets != 1 else ''} on <b>{domain}</b>. "
        f"{len(findings)} finding{'s were' if len(findings) != 1 else ' was'} recorded: "
        f"{', '.join(parts[:-1])} and {parts[-1]}."
    )
    kev = sum(1 for f in findings if f["kev"])
    if kev:
        text += f" <b>{kev}</b> {'are' if kev != 1 else 'is'} in CISA's Known Exploited Vulnerabilities catalog and should be fixed first."
    dorks = sum(1 for f in findings if f["dork"])
    if dorks:
        text += (
            f" <b>{dorks}</b> {'are' if dorks != 1 else 'is'} Google dork exposures confirmed on the host "
            "(exposed files, consoles or debug pages); they have no CVE and are scored by severity."
        )
    matches = sum(1 for f in findings if f["keyword_match"])
    if matches:
        text += (
            f" {matches} {'are' if matches != 1 else 'is'} possible CVE matches found by searching NVD for the detected "
            "service banner; they are leads to verify, not confirmed vulnerabilities."
        )
    return text


def _overview_table(findings):
    header = [Paragraph(h, _head_cell) for h in ("#", "SEVERITY", "CVE", "FINDING", "STATUS")]
    rows = [header]
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 1), (-1, -1), 0.5, PAPER_LINE),
        ("BOX", (0, 0), (-1, -1), 0.6, PAPER_LINE),
    ]
    for i, f in enumerate(findings, start=1):
        _, tint, text_color = _sev(f["severity"])
        sev = Paragraph(f'<font color="{text_color.hexval()}"><b>{_esc(f["severity"]).upper()}</b></font>', _cell)
        rows.append(
            [
                Paragraph(str(i), _cell_mono),
                sev,
                Paragraph(_esc(f["cve"]) if f["cve"] else "-", _cell_mono),
                Paragraph(_esc(f["title"]), _cell),
                Paragraph(_esc(f["status"]).replace("_", " "), _cell),
            ]
        )
        style.append(("BACKGROUND", (1, i), (1, i), tint))
    table = Table(rows, colWidths=[0.9 * cm, 2.0 * cm, 3.1 * cm, CONTENT_W - 8.2 * cm, 2.2 * cm], repeatRows=1)
    table.setStyle(TableStyle(style))
    return table


def _finding_block(index, f):
    bar_color, _, text_color = _sev(f["severity"])
    chips = [f'<font color="{text_color.hexval()}"><b>{_esc(f["severity"]).upper()}</b></font>']
    if f["cve"]:
        chips.append(f'<link href="https://nvd.nist.gov/vuln/detail/{_esc(f["cve"])}" color="#2c8752">{_esc(f["cve"])}</link>')
    if f["cvss"] is not None:
        chips.append(f"CVSS {f['cvss']:.1f}")
    chips.append(f"Risk score {f['risk']:.1f}")
    if f["dork"]:
        chips.append("Google dork exposure")
    elif f["config"]:
        chips.append("Configuration check")
    if f["kev"]:
        chips.append("<b>CISA KEV</b>")
    elif f["exploit"]:
        chips.append("Public exploit")
    chips.append(f"Status: {_esc(f['status']).replace('_', ' ')}")
    if f["asset"]:
        chips.append(f"Asset: {_esc(f['asset'])}")

    inner = [
        Paragraph(f"{index}. {_esc(f['title'])}", _finding_title),
        Paragraph("&nbsp;&nbsp;|&nbsp;&nbsp;".join(chips), _small),
    ]
    if f["description"]:
        inner.append(Spacer(1, 4))
        inner.append(Paragraph(_esc(_trim(f["description"])), _small))
    inner.append(Paragraph("RECOMMENDED MITIGATION", _label))
    for n, step in enumerate(f["steps"], start=1):
        inner.append(Paragraph(f"{n}.&nbsp;&nbsp;{_esc(step)}", _step))
    inner.append(Paragraph(f"<b>Suggested timeframe:</b> {_esc(f['timeframe'])}", _small))

    block = Table([["", inner]], colWidths=[0.2 * cm, CONTENT_W - 0.2 * cm])
    block.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), bar_color),
                ("BOX", (0, 0), (-1, -1), 0.6, PAPER_LINE),
                ("LEFTPADDING", (1, 0), (1, 0), 11),
                ("RIGHTPADDING", (1, 0), (1, 0), 11),
                ("TOPPADDING", (1, 0), (1, 0), 9),
                ("BOTTOMPADDING", (1, 0), (1, 0), 9),
                ("LEFTPADDING", (0, 0), (0, 0), 0),
                ("RIGHTPADDING", (0, 0), (0, 0), 0),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return [block, Spacer(1, 8)]


def _assets_table(assets):
    rows = [[Paragraph(h, _head_cell) for h in ("ASSET", "IP ADDRESS", "OPEN PORTS")]]
    for a in assets:
        rows.append([Paragraph(_esc(a["label"]), _cell_mono), Paragraph(_esc(a["ip"] or "-"), _cell_mono), Paragraph(_esc(a["ports"] or "-"), _cell_mono)])
    table = Table(rows, colWidths=[7.4 * cm, 3.6 * cm, CONTENT_W - 11.0 * cm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), INK),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("LINEBELOW", (0, 1), (-1, -1), 0.5, PAPER_LINE),
                ("BOX", (0, 0), (-1, -1), 0.6, PAPER_LINE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PAPER]),
            ]
        )
    )
    return table


# --------------------------------------------------------------------- entry


def build_pdf(file_path, data):
    """Render `data` to `file_path`.

    data keys: domain, generated_at (datetime), generated_by (str|None),
    counts {severity: n}, risk_score, port_total, assets [{label, ip, ports}],
    findings [{severity, cve, cvss, risk, dork, config, title, description, status, asset, kev,
    exploit, keyword_match, steps, timeframe}], notes [str].
    """
    doc = BaseDocTemplate(
        file_path,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=2.0 * cm,
        bottomMargin=2.0 * cm,
        title=f"Attack Surface Report - {data['domain']}",
        author="Attack Surface Management",
    )
    first = PageTemplate(
        id="first",
        frames=[Frame(MARGIN, 2.0 * cm, CONTENT_W, PAGE_H - BAND_H - 0.14 * cm - 2.0 * cm - 0.5 * cm, id="f1", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)],
        onPage=_cover_band(data),
    )
    later = PageTemplate(
        id="later",
        frames=[Frame(MARGIN, 2.0 * cm, CONTENT_W, PAGE_H - 2.0 * cm - 2.0 * cm, id="f2", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)],
        onPage=_later_header(data),
    )
    doc.addPageTemplates([first, later])

    story = [NextPageTemplate("later"), Spacer(1, 4)]
    story += [Paragraph(_executive_summary(data), _body), Spacer(1, 12), _stat_tiles(data), Spacer(1, 6)]

    story += _section("Findings by severity")
    story.append(_severity_bars(data["counts"]))

    findings = data["findings"]
    if findings:
        story += _section("Findings overview")
        story.append(_overview_table(findings))
        story += _section("Findings and recommended mitigation")
        intro = Paragraph(
            "Mitigation is the action that reduces or removes the risk a finding represents. Steps below are "
            "general guidance for each type of finding; confirm them against your own systems before applying.",
            _small,
        )
        gap = Spacer(1, 8)
        # keep the heading, intro and first finding on the same page
        intro.keepWithNext = 1
        gap.keepWithNext = 1
        story.extend([intro, gap])
        for i, f in enumerate(findings, start=1):
            story += _finding_block(i, f)
    else:
        story.append(Spacer(1, 10))
        story.append(Paragraph("No findings were recorded for this target.", _body))

    if data["assets"]:
        story += _section("Assets and exposed services")
        story.append(_assets_table(data["assets"]))

    story += _section("Scope and limitations")
    for note in data["notes"]:
        story.append(Paragraph(f"&bull;&nbsp;&nbsp;{_esc(note)}", _step))

    doc.build(story, canvasmaker=_NumberedCanvas)
