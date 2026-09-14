"""Forensic report generation: JSON (native), HTML (Jinja2), PDF (ReportLab).

All three builders accept EITHER the raw analyze_pcap() result (Session
objects) or the JSON-serializable form from result_to_dict() — sessions are
normalized at entry, so calling build_pdf(analyze_pcap(...)) directly works
(the worker, the API and tests all rely on this).
"""
from __future__ import annotations

import io
import json
import os
from datetime import datetime, timezone
import xml.sax.saxutils as saxutils

from jinja2 import Template
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

HERE = os.path.dirname(os.path.abspath(__file__))

PRODUCT = "Prahari"
PRODUCT_LINE = "Prahari — SecureMailScope · AI-Assisted Cryptographic Security Posture Assessment"
SCHEMA = "prahari.report/v1"
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _esc(val: any) -> str:
    """XML/HTML escape text for safe ReportLab Paragraph interpolation."""
    if val is None:
        return ""
    return saxutils.escape(str(val))


def _normalize(result: dict) -> dict:
    """Accept raw analyze_pcap() output or result_to_dict() form."""
    if "posture" not in result:
        return result
    sessions = result.get("sessions", [])
    if sessions and not isinstance(sessions[0], dict):
        from ..pipeline.runner import result_to_dict
        normalized = result_to_dict(result)
        result = dict(result)
        result.update({k: normalized[k] for k in
                       ("sessions", "findings", "advisories", "certificates",
                        "features", "anomaly_explanations", "posture",
                        "protocol_counts", "meta")})
    return result


def build_json(result: dict) -> bytes:
    result = _normalize(result)
    payload = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **result,
    }
    return json.dumps(payload, indent=2, default=str).encode()


def _grouped_findings(result: dict) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for f in result.get("findings", []):
        out.setdefault(f["severity"], []).append(f)
    for sev in out:
        out[sev].sort(key=lambda f: (f.get("session_id") is None, f.get("session_id") or ""))
    return {s: out[s] for s in SEV_ORDER if s in out}


def _compliance_table(findings: list[dict]) -> list[tuple[str, str, str, str, int]]:
    """Group findings by standard reference -> (reference, rule, title, severity, count)."""
    rows: dict[tuple, tuple[str, str, str, str, int]] = {}
    order: list[tuple] = []
    for f in findings:
        ref = f.get("reference") or "—"
        key = (ref, f["rule_id"])
        if key not in rows:
            rows[key] = (ref, f["rule_id"], f["title"], f["severity"], 1)
            order.append(key)
        else:
            r = rows[key]
            rows[key] = (r[0], r[1], r[2], r[3], r[4] + 1)
    return [rows[k] for k in order]


def _summary_text(result: dict) -> str:
    p = result.get("posture", {})
    n_sess = len(result.get("sessions", []))
    sev = p.get("severity_counts", {})
    worst = ", ".join("%d %s" % (sev[s], s) for s in SEV_ORDER if sev.get(s)) or "none"
    weak_protos = [k for k, v in result.get("protocol_counts", {}).items()
                   if k in ("smtp", "imap", "pop3")]
    lines = [
        "The analyzed capture contains %d reconstructed email session(s). "
        "The deterministic rule engine scored the cryptographic posture %d/100"
        % (n_sess, p.get("rule_score", p.get("score", 0))),
    ]
    if p.get("ml_adjustment"):
        lines[-1] += (" and the AI layer adjusted it by −%s to a fused score "
                     "of %d/100 (grade %s)"
                     % (p["ml_adjustment"], p.get("score", 0), p.get("grade", "—")))
    else:
        lines[-1] += " (grade %s)" % p.get("grade", "—")
    lines.append("Findings by severity: %s." % worst)
    if weak_protos:
        lines.append("Protocols observed: %s." %
                     ", ".join("%s (%d)" % (k, result["protocol_counts"][k])
                               for k in sorted(result["protocol_counts"])))
    if sev.get("critical"):
        lines.append("Critical exposures require immediate remediation: "
                     "cleartext credentials or deprecated cryptography were "
                     "observed on the wire and are exploitable by a passive "
                     "adversary.")
    return "\n\n".join(lines)


def _ml_sections_data(result: dict) -> tuple[bool, list[dict], dict]:
    """(ml_enabled, anomaly_explanations, risk_distribution)."""
    p = result.get("posture", {})
    ml = p.get("ml") or {}
    return bool(ml.get("enabled")), result.get("anomaly_explanations", []), \
        ml.get("risk_distribution") or {}


# ---------------------------------------------------------------------------
# COLOR PALETTE (Website Brand: Violet / Aubergine Theme)
# Derived from frontend/tokens.css and globals.css:
#   --color-primary: #6A2F8D (violet primary, hero bands, brand accents)
#   --color-accent:  #AD22FF (vivid violet accent)
#   --grad-deep:     #3A194D (deep aubergine elevated headers)
#   --color-paper:   #2A232A (aubergine canvas)
#   --color-paper-2: #F8F6F8 (light paper surface for print/PDF)
#   --color-paper-3: #EFECEF (elevated card / alt rows)
#   --color-ink:     #1D161D (dark ink for text)
#   --color-neutral: #564E56 (secondary text)
#   --color-muted:   #786C78 (tertiary labels & metadata)
#   --color-rule:    #D9D9D9 (borders)
# ---------------------------------------------------------------------------
VIOLET_PRIMARY = colors.HexColor("#6A2F8D")  # Website primary violet (hero banner, section titles)
AUBERGINE_DEEP = colors.HexColor("#3A194D")  # Website deep aubergine (table dark headers)
INK_DARK       = colors.HexColor("#1D161D")  # Website ink (primary body text, dark values)
NEUTRAL_MID    = colors.HexColor("#564E56")  # Website neutral (secondary text)
MUTED_TEXT     = colors.HexColor("#786C78")  # Website muted (labels, metadata, timestamps)
BORDER_LIGHT   = colors.HexColor("#D9D9D9")  # Website rule (card & table borders)
BORDER_MID     = colors.HexColor("#C4BCC4")  # Header divider / subtle rule
SURFACE_LIGHT  = colors.HexColor("#F8F6F8")  # Website paper-2 (shaded cards, alt rows)
SURFACE_ALT    = colors.HexColor("#EFECEF")  # Website paper-3 (elevated card backgrounds)

# Legacy aliases for internal references
NAVY_DEEP = VIOLET_PRIMARY
NAVY_CARD = AUBERGINE_DEEP
SLATE_DARK = INK_DARK
SLATE_MID = NEUTRAL_MID
SLATE_MUTED = MUTED_TEXT

SEV_CONFIG = {
    "critical": {
        "text": colors.HexColor("#991B1B"),
        "bg": colors.HexColor("#FEF2F2"),
        "border": colors.HexColor("#EF4444"),
        "badge": colors.HexColor("#DC2626"),
        "name": "CRITICAL",
    },
    "high": {
        "text": colors.HexColor("#9A3412"),
        "bg": colors.HexColor("#FFF7ED"),
        "border": colors.HexColor("#F97316"),
        "badge": colors.HexColor("#EA580C"),
        "name": "HIGH",
    },
    "medium": {
        "text": colors.HexColor("#854D0E"),
        "bg": colors.HexColor("#FEFCE8"),
        "border": colors.HexColor("#EAB308"),
        "badge": colors.HexColor("#CA8A04"),
        "name": "MEDIUM",
    },
    "low": {
        "text": colors.HexColor("#075985"),
        "bg": colors.HexColor("#F0F9FF"),
        "border": colors.HexColor("#38BDF8"),
        "badge": colors.HexColor("#0284C7"),
        "name": "LOW",
    },
    "info": {
        "text": NEUTRAL_MID,
        "bg": SURFACE_LIGHT,
        "border": BORDER_MID,
        "badge": MUTED_TEXT,
        "name": "INFO",
    },
}

GRADE_COLORS = {
    "A": colors.HexColor("#059669"),
    "B": colors.HexColor("#16A34A"),
    "C": colors.HexColor("#D97706"),
    "D": colors.HexColor("#EA580C"),
    "F": colors.HexColor("#DC2626"),
}


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas that automatically adds running headers, footers,
    and accurate 'Page X of Y' pagination across the entire document."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_decorations(self, total_pages: int):
        self.saveState()
        w = 210 * mm
        h = 297 * mm
        margin = 14 * mm

        # Running header on page 2+
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 7.5)
            self.setFillColor(VIOLET_PRIMARY)
            self.drawString(margin, h - 9.5 * mm, "PRAHARI // SECUREMAILSCOPE")
            self.setFont("Helvetica", 7.5)
            self.setFillColor(MUTED_TEXT)
            self.drawString(margin + 52 * mm, h - 9.5 * mm, "— Cryptographic Security Posture Assessment")
            self.drawRightString(w - margin, h - 9.5 * mm, "OFFICIAL FORENSIC AUDIT")

            self.setStrokeColor(BORDER_MID)
            self.setLineWidth(0.5)
            self.line(margin, h - 11.5 * mm, w - margin, h - 11.5 * mm)

        # Running footer on all pages
        self.setStrokeColor(BORDER_LIGHT)
        self.setLineWidth(0.5)
        self.line(margin, 12 * mm, w - margin, 12 * mm)

        self.setFont("Helvetica-Bold", 7)
        self.setFillColor(VIOLET_PRIMARY)
        self.drawString(margin, 8 * mm, "PRAHARI")
        self.setFont("Helvetica", 7)
        self.setFillColor(MUTED_TEXT)
        self.drawString(margin + 15 * mm, 8 * mm, "· SIH 2026 NTRO (PS-26159) · Passive PCAP Cryptanalysis · Zero Active Probing")

        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(INK_DARK)
        self.drawRightString(w - margin, 8 * mm, f"Page {self._pageNumber} of {total_pages}")

        self.restoreState()


def build_pdf(result: dict, scan_name: str = "capture.pcap") -> bytes:
    """Generate an executive-grade forensic PDF posture assessment report."""
    result = _normalize(result)
    ml_on, anomalies, risk_dist = _ml_sections_data(result)
    buf = io.BytesIO()

    # Printable width: 210mm - 28mm = 182mm
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=13 * mm,
        bottomMargin=15 * mm,
        title=f"Prahari Posture Report — {scan_name}",
        author="Prahari Security Engine",
    )

    pw = 182 * mm  # Content printable width

    # Custom typography styles
    style_sec_title = ParagraphStyle(
        "SecTitle",
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=VIOLET_PRIMARY,
        spaceBefore=4,
        spaceAfter=2,
        keepWithNext=True,
    )

    style_sec_sub = ParagraphStyle(
        "SecSub",
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        textColor=MUTED_TEXT,
        spaceAfter=4,
        keepWithNext=True,
    )

    style_normal = ParagraphStyle(
        "Norm",
        fontName="Helvetica",
        fontSize=7.5,
        leading=10.5,
        textColor=INK_DARK,
    )

    style_mono = ParagraphStyle(
        "Mono",
        fontName="Courier-Bold",
        fontSize=7,
        leading=8.5,
        textColor=VIOLET_PRIMARY,
    )

    story = []

    # -----------------------------------------------------------------------
    # 1. EXECUTIVE HERO BANNER
    # -----------------------------------------------------------------------
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    esc_scan_name = _esc(scan_name)
    left_banner = [
        Paragraph(
            "<font color='#6A2F8D' size='7'><b>SMART INDIA HACKATHON 2026 · NTRO PROBLEM STATEMENT 26159</b></font>",
            ParagraphStyle("BTag", leading=8.5),
        ),
        Spacer(1, 1.5 * mm),
        Paragraph(
            "<font color='#1D161D' size='20'><b>PRAHARI</b></font> "
            "<font color='#6A2F8D' size='11'><b>| SECUREMAILSCOPE</b></font>",
            ParagraphStyle("BTitle", leading=21),
        ),
        Paragraph(
            "<font color='#564E56' size='7.5'>Passive Cryptographic Posture Assessment &amp; Forensic Analysis</font>",
            ParagraphStyle("BSub", leading=10),
        ),
    ]

    right_banner = [
        Paragraph(
            f"<font color='#786C78' size='6.8'>TARGET ARTIFACT</font><br/>"
            f"<font color='#6A2F8D' size='8'><b>{esc_scan_name}</b></font>",
            ParagraphStyle("BRight1", leading=9.5, alignment=2),
        ),
        Spacer(1, 1.5 * mm),
        Paragraph(
            f"<font color='#786C78' size='6.8'>TIMESTAMP: </font>"
            f"<font color='#1D161D' size='7'><b>{now_str}</b></font><br/>"
            f"<font color='#786C78' size='6.8'>STANDARD: </font>"
            f"<font color='#1D161D' size='7'><b>NIST SP 800-52r2 · BSI · CERT-In</b></font>",
            ParagraphStyle("BRight2", leading=9, alignment=2),
        ),
    ]

    banner_table = Table(
        [[left_banner, right_banner]],
        colWidths=[116 * mm, 66 * mm],
    )
    banner_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SURFACE_LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.75, BORDER_LIGHT),
            ("LINEBEFORE", (0, 0), (0, -1), 3.0, VIOLET_PRIMARY),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5 * mm),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5 * mm),
            ("LEFTPADDING", (0, 0), (-1, -1), 5 * mm),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5 * mm),
        ])
    )
    story.append(banner_table)
    story.append(Spacer(1, 3.5 * mm))

    # -----------------------------------------------------------------------
    # 2. EXECUTIVE POSTURE SCORECARD & METRICS DASHBOARD
    # -----------------------------------------------------------------------
    posture = result.get("posture", {})
    grade = posture.get("grade", "F")
    score = posture.get("score", 0)
    rule_score = posture.get("rule_score", score)
    ml_adj = posture.get("ml_adjustment", 0)
    sev_counts = posture.get("severity_counts", {})
    grade_col = GRADE_COLORS.get(grade, colors.HexColor("#DC2626"))

    if score >= 85:
        verdict_title = "STRONG POSTURE"
        verdict_desc = "Meets NIST & CERT-In baseline"
    elif score >= 70:
        verdict_title = "MODERATE RISK"
        verdict_desc = "Minor cryptographic flaws"
    elif score >= 50:
        verdict_title = "ELEVATED RISK"
        verdict_desc = "Deprecated suites or weak keys"
    else:
        verdict_title = "CRITICAL RISK"
        verdict_desc = "Immediate remediation required"

    # Card 1: Grade & Score
    c1 = [
        Paragraph("<font size='6.8' color='#786C78'><b>OVERALL POSTURE</b></font>", ParagraphStyle("C1L", leading=8.5)),
        Spacer(1, 1 * mm),
        Paragraph(
            f"<font size='20' color='{grade_col.hexval()}'><b>GRADE {grade}</b></font>",
            ParagraphStyle("C1G", leading=20),
        ),
        Paragraph(
            f"<font size='10.5' color='{grade_col.hexval()}'><b>{score}</b></font><font size='7.5' color='#786C78'> / 100</font>",
            ParagraphStyle("C1S", leading=11),
        ),
        Spacer(1, 1 * mm),
        Paragraph(
            f"<b><font size='7.2' color='{grade_col.hexval()}'>{verdict_title}</font></b><br/>"
            f"<font size='6.2' color='#786C78'>{verdict_desc}</font>",
            ParagraphStyle("C1D", leading=8),
        ),
    ]

    # Card 2: Score Fusion
    c2 = [
        Paragraph("<font size='6.8' color='#786C78'><b>SCORE FUSION ENGINE</b></font>", ParagraphStyle("C2L", leading=8.5)),
        Spacer(1, 1 * mm),
        Paragraph(
            f"<font size='7' color='#564E56'>Rule score: </font>"
            f"<b><font size='7.5' color='#1D161D'>{rule_score}/100</font></b>",
            ParagraphStyle("C2R", leading=9.5),
        ),
        Paragraph(
            f"<font size='7' color='#564E56'>AI ML adjustment: </font>"
            f"<b><font size='7.5' color='#DC2626'>−{ml_adj} pts</font></b>",
            ParagraphStyle("C2A", leading=9.5),
        ),
        Paragraph(
            f"<font size='7' color='#564E56'>Fused posture: </font>"
            f"<b><font size='8' color='{grade_col.hexval()}'>{score}/100</font></b>",
            ParagraphStyle("C2F", leading=10),
        ),
        Spacer(1, 1 * mm),
        Paragraph(
            "<font size='6.2' color='#786C78'>Score = clamp(Rule − Adj, 0, 100)<br/>Bounded adjustment ≤10 pts max</font>",
            ParagraphStyle("C2M", leading=7.5),
        ),
    ]

    # Card 3: Severity breakdown
    c3 = [
        Paragraph("<font size='6.8' color='#786C78'><b>FINDINGS BREAKDOWN</b></font>", ParagraphStyle("C3L", leading=8.5)),
        Spacer(1, 1 * mm),
        Paragraph(
            f"<font color='#DC2626' size='7.5'>● <b>{sev_counts.get('critical', 0)} Critical</b></font>&nbsp;&nbsp;"
            f"<font color='#EA580C' size='7.5'>● <b>{sev_counts.get('high', 0)} High</b></font>",
            ParagraphStyle("C31", leading=9.5),
        ),
        Paragraph(
            f"<font color='#CA8A04' size='7.5'>● <b>{sev_counts.get('medium', 0)} Medium</b></font>&nbsp;&nbsp;"
            f"<font color='#0284C7' size='7.5'>● <b>{sev_counts.get('low', 0)} Low</b></font>",
            ParagraphStyle("C32", leading=9.5),
        ),
        Paragraph(
            f"<font color='#786C78' size='7.5'>● <b>{sev_counts.get('info', 0)} Informational</b></font>",
            ParagraphStyle("C33", leading=9.5),
        ),
        Spacer(1, 1 * mm),
        Paragraph(
            f"<font size='6.2' color='#786C78'>Total findings: {len(result.get('findings', []))}</font>",
            ParagraphStyle("C3T", leading=7.5),
        ),
    ]

    # Card 4: Scope & Telemetry
    proto_items = [f"{k.upper()} ({v})" for k, v in sorted(result.get("protocol_counts", {}).items())]
    proto_str = ", ".join(proto_items) if proto_items else "None"
    c4 = [
        Paragraph("<font size='6.8' color='#786C78'><b>SCOPE &amp; TELEMETRY</b></font>", ParagraphStyle("C4L", leading=8.5)),
        Spacer(1, 1 * mm),
        Paragraph(
            f"<font size='7' color='#564E56'>Sessions: </font>"
            f"<b><font size='7.5' color='#1D161D'>{len(result.get('sessions', []))}</font></b>",
            ParagraphStyle("C4S", leading=9.5),
        ),
        Paragraph(
            f"<font size='7' color='#564E56'>Protocols: </font>"
            f"<b><font size='7.5' color='#1D161D'>{proto_str}</font></b>",
            ParagraphStyle("C4P", leading=9.5),
        ),
        Paragraph(
            f"<font size='7' color='#564E56'>Certificates: </font>"
            f"<b><font size='7.5' color='#1D161D'>{len(result.get('certificates', []))}</font></b>",
            ParagraphStyle("C4C", leading=9.5),
        ),
        Spacer(1, 1 * mm),
        Paragraph(
            "<font size='6.2' color='#786C78'>Passive TCP stream reassembly</font>",
            ParagraphStyle("C4Sub", leading=7.5),
        ),
    ]

    card_table = Table(
        [[c1, c2, c3, c4]],
        colWidths=[46 * mm, 50 * mm, 44 * mm, 42 * mm],
    )
    card_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#FEF2F2") if score < 70 else colors.HexColor("#F0FDF4")),
            ("BACKGROUND", (1, 0), (-1, -1), SURFACE_LIGHT),
            ("BOX", (0, 0), (0, 0), 1, grade_col),
            ("BOX", (1, 0), (1, 0), 0.5, BORDER_LIGHT),
            ("BOX", (2, 0), (2, 0), 0.5, BORDER_LIGHT),
            ("BOX", (3, 0), (3, 0), 0.5, BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 2.8 * mm),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.8 * mm),
            ("LEFTPADDING", (0, 0), (-1, -1), 2.8 * mm),
            ("RIGHTPADDING", (0, 0), (-1, -1), 2.8 * mm),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )
    story.append(card_table)
    story.append(Spacer(1, 3.5 * mm))

    # -----------------------------------------------------------------------
    # 3. EXECUTIVE THREAT NARRATIVE / ALERT CALLOUT
    # -----------------------------------------------------------------------
    has_crit = sev_counts.get("critical", 0) > 0
    has_high = sev_counts.get("high", 0) > 0

    if has_crit or has_high:
        alert_bg = colors.HexColor("#FEF2F2")
        alert_border = colors.HexColor("#EF4444")
        alert_title = "<font color='#991B1B' size='7.5'><b>[!] CRITICAL SECURITY EXPOSURE IDENTIFIED</b></font>"
        alert_body = (
            f"The analyzed capture contains <b>{len(result.get('sessions', []))}</b> reconstructed email session(s). "
            f"The deterministic rule engine scored the cryptographic posture <b>{rule_score}/100</b>, and the AI layer "
            f"adjusted it by <b>−{ml_adj}</b> to a fused score of <b>{score}/100 (Grade {grade})</b>.<br/>"
            f"<b>Urgent:</b> Cleartext credentials or severely deprecated cryptography were observed on the wire. "
            f"Network eavesdroppers or rogue on-path actors can extract confidential mail contents and authentication "
            f"tokens without requiring active tampering or certificate forgery."
        )
    else:
        alert_bg = colors.HexColor("#F0FDF4")
        alert_border = colors.HexColor("#16A34A")
        alert_title = "<font color='#166534' size='7.5'><b>[✓] CRYPTOGRAPHIC POSTURE BASELINE SATISFIED</b></font>"
        alert_body = (
            f"The analyzed capture contains <b>{len(result.get('sessions', []))}</b> reconstructed email session(s). "
            f"The cryptographic posture scored <b>{score}/100 (Grade {grade})</b>. Reconstructed sessions enforce "
            f"modern TLS protocols with secure cipher suites, compliant with NIST SP 800-52r2 guidelines."
        )

    alert_content = [
        Paragraph(alert_title, ParagraphStyle("ATitle", leading=9.5)),
        Spacer(1, 0.8 * mm),
        Paragraph(alert_body, ParagraphStyle("ABody", fontName="Helvetica", fontSize=7, leading=9.5, textColor=SLATE_DARK)),
    ]
    alert_table = Table([[alert_content]], colWidths=[pw])
    alert_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), alert_bg),
            ("BOX", (0, 0), (-1, -1), 0.5, alert_border),
            ("LINELEFT", (0, 0), (-1, -1), 2.5, alert_border),
            ("TOPPADDING", (0, 0), (-1, -1), 2 * mm),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2 * mm),
            ("LEFTPADDING", (0, 0), (-1, -1), 3 * mm),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3 * mm),
        ])
    )
    story.append(alert_table)
    story.append(Spacer(1, 3.5 * mm))

    # -----------------------------------------------------------------------
    # 4. SECURITY FINDINGS & DEFICIENCIES
    # -----------------------------------------------------------------------
    story.append(Paragraph("1. Security Findings &amp; Deficiencies", style_sec_title))
    story.append(Paragraph("Violations detected by deterministic cryptographic rule evaluation against national standards.", style_sec_sub))

    grouped = _grouped_findings(result)
    if not grouped:
        no_find = Table(
            [[Paragraph("<font color='#059669'><b>No security findings detected.</b> All analyzed sessions comply with configured rules.</font>", style_normal)]],
            colWidths=[pw],
        )
        no_find.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0FDF4")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#86EFAC")),
            ("PADDING", (0, 0), (-1, -1), 2.5 * mm),
        ]))
        story.append(no_find)
        story.append(Spacer(1, 3.5 * mm))
    else:
        for sev in SEV_ORDER:
            if sev not in grouped:
                continue
            items = grouped[sev]
            cfg = SEV_CONFIG.get(sev, SEV_CONFIG["info"])

            # Severity Banner
            banner_row = [
                Paragraph(f"<b><font color='{cfg['text'].hexval()}' size='7.5'>● {cfg['name']} ({len(items)})</font></b>", ParagraphStyle("SBLeft", leading=9.5)),
                Paragraph(f"<font color='{cfg['text'].hexval()}' size='6.8'>Weighted impact per finding · Standards violation</font>", ParagraphStyle("SBRight", leading=8.5, alignment=2)),
            ]
            sev_header_table = Table([banner_row], colWidths=[100 * mm, 82 * mm])
            sev_header_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), cfg["bg"]),
                ("BOX", (0, 0), (-1, -1), 0.5, cfg["border"]),
                ("TOPPADDING", (0, 0), (-1, -1), 1.2 * mm),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1.2 * mm),
                ("LEFTPADDING", (0, 0), (-1, -1), 2 * mm),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2 * mm),
            ]))

            rows = [[
                Paragraph("<b>Session</b>", ParagraphStyle("TH1", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
                Paragraph("<b>Deficiency &amp; Technical Risk</b>", ParagraphStyle("TH2", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
                Paragraph("<b>Standard Reference</b>", ParagraphStyle("TH3", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
                Paragraph("<b>Remediation Guidance</b>", ParagraphStyle("TH4", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
            ]]

            for f in items:
                sid_display = _esc(f.get("session_id") or "Global")
                cell_sess = Paragraph(f"<font color='#6A2F8D'><b>{sid_display}</b></font>", style_mono)
                cell_desc = Paragraph(
                    f"<b>{_esc(f.get('title', '—'))}</b><br/>"
                    f"<font color='#564E56' size='6.5'>{_esc(f.get('description', ''))}</font>",
                    ParagraphStyle("FDesc", fontName="Helvetica", fontSize=7, leading=9),
                )
                cell_ref = Paragraph(
                    f"<font color='#564E56' size='6.5'>{_esc(f.get('reference', '—'))}</font>",
                    ParagraphStyle("FRef", fontName="Helvetica", fontSize=6.5, leading=8),
                )
                cell_rem = Paragraph(
                    f"<font color='#1D161D' size='6.5'>{_esc(f.get('remediation', '—'))}</font>",
                    ParagraphStyle("FRem", fontName="Helvetica", fontSize=6.5, leading=8),
                )
                rows.append([cell_sess, cell_desc, cell_ref, cell_rem])

            find_table = Table(rows, colWidths=[20 * mm, 62 * mm, 48 * mm, 52 * mm], repeatRows=1)
            find_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), AUBERGINE_DEEP),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER_LIGHT),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SURFACE_LIGHT]),
                ("TOPPADDING", (0, 0), (-1, -1), 1.8 * mm),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1.8 * mm),
                ("LEFTPADDING", (0, 0), (-1, -1), 1.8 * mm),
                ("RIGHTPADDING", (0, 0), (-1, -1), 1.8 * mm),
            ]))

            story.append(sev_header_table)
            story.append(find_table)
            story.append(Spacer(1, 3 * mm))

    # -----------------------------------------------------------------------
    # 5. ADVISORIES (Optional)
    # -----------------------------------------------------------------------
    advisories = result.get("advisories", [])
    if advisories:
        story.append(Paragraph("Cryptographic Advisories (Non-Scored Status Quo Signals)", style_sec_title))
        story.append(Paragraph("Posture signals that reflect current industry transition status rather than immediate misconfiguration.", style_sec_sub))

        adv_rows = [[
            Paragraph("<b>Session</b>", ParagraphStyle("ATH1", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
            Paragraph("<b>Advisory Title &amp; Context</b>", ParagraphStyle("ATH2", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
            Paragraph("<b>Migration Guidance</b>", ParagraphStyle("ATH3", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
        ]]
        for a in advisories:
            adv_rows.append([
                Paragraph(f"<font color='#6A2F8D'><b>{_esc(a.get('session_id') or '—')}</b></font>", style_mono),
                Paragraph(f"<b>{_esc(a.get('title'))}</b><br/><font color='#786C78' size='6.5'>{_esc(a.get('description', ''))}</font>", ParagraphStyle("AD1", fontName="Helvetica", fontSize=7, leading=9)),
                Paragraph(f"<font color='#564E56' size='6.5'>{_esc(a.get('remediation', '—'))}</font>", ParagraphStyle("AD2", fontName="Helvetica", fontSize=6.5, leading=8)),
            ])
        adv_table = Table(adv_rows, colWidths=[20 * mm, 86 * mm, 76 * mm], repeatRows=1)
        adv_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), AUBERGINE_DEEP),
            ("GRID", (0, 0), (-1, -1), 0.4, BORDER_LIGHT),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SURFACE_LIGHT]),
            ("PADDING", (0, 0), (-1, -1), 1.8 * mm),
        ]))
        story.append(adv_table)
        story.append(Spacer(1, 3.5 * mm))

    # -----------------------------------------------------------------------
    # 6. RECONSTRUCTED SESSIONS INVENTORY
    # -----------------------------------------------------------------------
    story.append(Paragraph("2. Reconstructed Session Inventory", style_sec_title))
    story.append(Paragraph("Granular telemetry extracted via passive TCP stream reassembly and TLS record layer parsing.", style_sec_sub))

    sess_rows = [[
        Paragraph("<b>ID</b>", ParagraphStyle("STH1", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
        Paragraph("<b>Proto</b>", ParagraphStyle("STH2", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
        Paragraph("<b>Transport</b>", ParagraphStyle("STH3", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
        Paragraph("<b>TLS Ver</b>", ParagraphStyle("STH4", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
        Paragraph("<b>Negotiated Cipher Suite</b>", ParagraphStyle("STH5", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
        Paragraph("<b>PFS</b>", ParagraphStyle("STH6", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
        Paragraph("<b>Grade</b>", ParagraphStyle("STH7", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
        Paragraph("<b>ML Risk</b>", ParagraphStyle("STH8", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
    ]]

    for s in result.get("sessions", []):
        s_grade = s.get("grade", "—")
        s_col = GRADE_COLORS.get(s_grade, SLATE_DARK)
        pfs_str = "Yes" if s.get("pfs") is True else ("No" if s.get("pfs") is False else "—")
        pfs_col = "#059669" if pfs_str == "Yes" else ("#DC2626" if pfs_str == "No" else "#786C78")

        ml_obj = s.get("ml_risk") or {}
        ml_label = ml_obj.get("label", "—")
        ml_badge_col = "#DC2626" if ml_label in ("critical", "high") else ("#059669" if ml_label == "clean" else "#786C78")

        cipher_str = _esc(s.get("cipher_suite") or "—")
        sess_rows.append([
            Paragraph(f"<font color='#6A2F8D'><b>{_esc(s.get('session_id', '—'))}</b></font>", style_mono),
            Paragraph(f"<b>{_esc((s.get('protocol') or '').upper())}</b>", ParagraphStyle("SP", fontName="Helvetica", fontSize=6.8)),
            Paragraph(f"<font color='#564E56'>{_esc(s.get('transport', '—'))}</font>", ParagraphStyle("ST", fontName="Helvetica", fontSize=6.8)),
            Paragraph(f"<b>{_esc(s.get('tls_version') or '—')}</b>", ParagraphStyle("SV", fontName="Helvetica", fontSize=6.8)),
            Paragraph(f"<font color='#1D161D' size='6.5'>{cipher_str}</font>", ParagraphStyle("SC", fontName="Courier", fontSize=6.5, leading=7.8)),
            Paragraph(f"<font color='{pfs_col}'><b>{pfs_str}</b></font>", ParagraphStyle("SPF", fontName="Helvetica", fontSize=6.8)),
            Paragraph(f"<b><font color='{s_col.hexval()}'>{s_grade} ({s.get('risk_score', 0)})</font></b>", ParagraphStyle("SG", fontName="Helvetica", fontSize=6.8)),
            Paragraph(f"<font color='{ml_badge_col}'><b>{ml_label}</b></font>", ParagraphStyle("SM", fontName="Helvetica", fontSize=6.8)),
        ])

    sess_table = Table(sess_rows, colWidths=[18 * mm, 14 * mm, 20 * mm, 17 * mm, 61 * mm, 14 * mm, 20 * mm, 18 * mm], repeatRows=1)
    sess_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), AUBERGINE_DEEP),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER_LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SURFACE_LIGHT]),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5 * mm),
        ("LEFTPADDING", (0, 0), (-1, -1), 1.5 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 1.5 * mm),
    ]))
    story.append(sess_table)
    story.append(Spacer(1, 3.5 * mm))

    # -----------------------------------------------------------------------
    # 7. AI ANOMALY & THREAT DETECTION
    # -----------------------------------------------------------------------
    story.append(Paragraph("3. AI Anomaly &amp; Statistical Threat Analysis", style_sec_title))
    story.append(Paragraph("Unsupervised Isolation Forest model detecting multidimensional outliers against baseline email behavior.", style_sec_sub))

    if not ml_on:
        ml_box = Table(
            [[Paragraph("<font color='#786C78'>AI ML layer was not enabled for this scan. Rule evaluation is fully active.</font>", style_normal)]],
            colWidths=[pw],
        )
        ml_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SURFACE_LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ("PADDING", (0, 0), (-1, -1), 2.5 * mm),
        ]))
        story.append(ml_box)
    elif anomalies:
        anom_rows = [[
            Paragraph("<b>Session</b>", ParagraphStyle("ANH1", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
            Paragraph("<b>Anomaly Score</b>", ParagraphStyle("ANH2", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
            Paragraph("<b>Risk Class</b>", ParagraphStyle("ANH3", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
            Paragraph("<b>Feature Deviation &amp; Z-Scores (|z| &gt; 2 indicates significant outlier)</b>", ParagraphStyle("ANH4", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
        ]]
        for a in anomalies:
            feats = ", ".join(f"{_esc(x['feature']).replace('_', ' ')} at {x['z']}σ (val {x['value']})" for x in a.get("top_features", []))
            ml_risk = a.get("ml_risk") or {}
            anom_rows.append([
                Paragraph(f"<font color='#6A2F8D'><b>{_esc(a.get('session_id', '—'))}</b></font>", style_mono),
                Paragraph(f"<b><font color='#DC2626'>{a.get('score', 0)}</font></b>", ParagraphStyle("ANS", fontName="Helvetica", fontSize=6.8)),
                Paragraph(f"<b>{_esc(ml_risk.get('label', '—'))}</b>", ParagraphStyle("ANR", fontName="Helvetica", fontSize=6.8)),
                Paragraph(f"<font color='#564E56' size='6.5'>{feats}</font>", ParagraphStyle("ANF", fontName="Helvetica", fontSize=6.5, leading=8)),
            ])
        anom_table = Table(anom_rows, colWidths=[20 * mm, 24 * mm, 24 * mm, 114 * mm], repeatRows=1)
        anom_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), AUBERGINE_DEEP),
            ("GRID", (0, 0), (-1, -1), 0.4, BORDER_LIGHT),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SURFACE_LIGHT]),
            ("PADDING", (0, 0), (-1, -1), 1.8 * mm),
        ]))
        story.append(anom_table)
    else:
        norm_box = Table(
            [[Paragraph("<font color='#059669'><b>No statistical anomalies detected.</b> All reconstructed sessions conform to healthy operational baselines learned from the training corpus.</font>", style_normal)]],
            colWidths=[pw],
        )
        norm_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0FDF4")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#86EFAC")),
            ("PADDING", (0, 0), (-1, -1), 2.5 * mm),
        ]))
        story.append(norm_box)
    story.append(Spacer(1, 3.5 * mm))

    # -----------------------------------------------------------------------
    # 8. X.509 CERTIFICATE INVENTORY (Deduplicated by Fingerprint)
    # -----------------------------------------------------------------------
    all_certs = result.get("certificates", [])
    story.append(Paragraph("4. X.509 Certificate Inventory &amp; Validation", style_sec_title))
    story.append(Paragraph("Cryptographic parameter validation for observed digital identity certificates.", style_sec_sub))

    # Deduplicate certificates by fingerprint to prevent table bloat
    unique_certs = []
    seen_fps = set()
    for c in all_certs:
        fp = c.get("fingerprint_sha256")
        if fp and fp not in seen_fps:
            seen_fps.add(fp)
            unique_certs.append(c)
        elif not fp:
            unique_certs.append(c)

    if unique_certs:
        cert_rows = [[
            Paragraph("<b>Subject Common Name</b>", ParagraphStyle("CH1", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
            Paragraph("<b>Key &amp; Algorithm</b>", ParagraphStyle("CH2", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
            Paragraph("<b>Signature</b>", ParagraphStyle("CH3", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
            Paragraph("<b>Validity Status</b>", ParagraphStyle("CH4", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
            Paragraph("<b>SHA-256 Fingerprint (truncated)</b>", ParagraphStyle("CH5", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
        ]]
        for c in unique_certs:
            is_exp = c.get("is_expired")
            val_status = f"{_esc(c.get('not_after', '')[:10])}"
            if is_exp:
                val_status += "<br/><b><font color='#DC2626'>[EXPIRED]</font></b>"

            cert_rows.append([
                Paragraph(f"<b>{_esc(c.get('subject_cn', '—'))}</b>", ParagraphStyle("CN", fontName="Helvetica", fontSize=6.8)),
                Paragraph(f"{_esc(c.get('key_algorithm', ''))} {_esc(c.get('key_length', ''))}b", ParagraphStyle("CK", fontName="Helvetica", fontSize=6.8)),
                Paragraph(f"{_esc(c.get('signature_hash', '—'))}", ParagraphStyle("CS", fontName="Helvetica", fontSize=6.8)),
                Paragraph(val_status, ParagraphStyle("CV", fontName="Helvetica", fontSize=6.8, leading=8)),
                Paragraph(f"<font color='#6A2F8D'>{_esc(c.get('fingerprint_sha256', '')[:32])}…</font>", style_mono),
            ])
        cert_table = Table(cert_rows, colWidths=[42 * mm, 24 * mm, 24 * mm, 32 * mm, 60 * mm], repeatRows=1)
        cert_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), AUBERGINE_DEEP),
            ("GRID", (0, 0), (-1, -1), 0.4, BORDER_LIGHT),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SURFACE_LIGHT]),
            ("PADDING", (0, 0), (-1, -1), 1.8 * mm),
        ]))
        story.append(cert_table)
    else:
        no_cert = Table(
            [[Paragraph("<font color='#786C78'><b>No X.509 certificates observed.</b> Reconstructed sessions were either plaintext email protocols or TLS handshakes did not complete.</font>", style_normal)]],
            colWidths=[pw],
        )
        no_cert.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SURFACE_LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ("PADDING", (0, 0), (-1, -1), 2.5 * mm),
        ]))
        story.append(no_cert)
    story.append(Spacer(1, 3.5 * mm))

    # -----------------------------------------------------------------------
    # 9. COMPLIANCE MAPPING MATRIX
    # -----------------------------------------------------------------------
    comp = _compliance_table(result.get("findings", []))
    story.append(Paragraph("5. Standards &amp; Regulatory Compliance Matrix", style_sec_title))
    story.append(Paragraph("Cross-reference mapping observed findings to NIST SP 800-52r2, RFC 8996, BSI TR-02102, and CERT-In CIAD-2020-04.", style_sec_sub))

    if comp:
        comp_rows = [[
            Paragraph("<b>Regulatory Standard &amp; Clause</b>", ParagraphStyle("COH1", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
            Paragraph("<b>Rule ID</b>", ParagraphStyle("COH2", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
            Paragraph("<b>Requirement Description</b>", ParagraphStyle("COH3", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
            Paragraph("<b>Severity</b>", ParagraphStyle("COH4", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
            Paragraph("<b>Count</b>", ParagraphStyle("COH5", fontName="Helvetica-Bold", fontSize=6.8, textColor=colors.white)),
        ]]
        for ref, rid, title, sev, n in comp:
            s_col = SEV_CONFIG.get(sev, SEV_CONFIG["info"])
            comp_rows.append([
                Paragraph(f"<font color='#1D161D'><b>{_esc(ref)}</b></font>", ParagraphStyle("CORef", fontName="Helvetica", fontSize=6.8, leading=8.5)),
                Paragraph(f"<font color='#6A2F8D'><b>{_esc(rid)}</b></font>", style_mono),
                Paragraph(f"{_esc(title)}", ParagraphStyle("COTit", fontName="Helvetica", fontSize=6.8, leading=8)),
                Paragraph(f"<b><font color='{s_col['badge'].hexval()}'>{sev.upper()}</font></b>", ParagraphStyle("COSev", fontName="Helvetica", fontSize=6.8)),
                Paragraph(f"<b>{n}</b>", ParagraphStyle("CON", fontName="Helvetica", fontSize=6.8, alignment=1)),
            ])
        comp_table = Table(comp_rows, colWidths=[70 * mm, 22 * mm, 54 * mm, 22 * mm, 14 * mm], repeatRows=1)
        comp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), AUBERGINE_DEEP),
            ("GRID", (0, 0), (-1, -1), 0.4, BORDER_LIGHT),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SURFACE_LIGHT]),
            ("PADDING", (0, 0), (-1, -1), 1.8 * mm),
        ]))
        story.append(comp_table)
    else:
        no_comp = Table(
            [[Paragraph("<font color='#059669'><b>All compliance baselines satisfied.</b> No regulatory infractions detected across evaluated frameworks.</font>", style_normal)]],
            colWidths=[pw],
        )
        no_comp.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0FDF4")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#86EFAC")),
            ("PADDING", (0, 0), (-1, -1), 2.5 * mm),
        ]))
        story.append(no_comp)
    story.append(Spacer(1, 3.5 * mm))

    # -----------------------------------------------------------------------
    # 10. METHODOLOGY & AUDIT ATTESTATION APPENDIX
    # -----------------------------------------------------------------------
    appendix_text = (
        "<b>Scoring Methodology &amp; Mathematical Fusion:</b> The deterministic rule engine evaluates "
        "25 cryptographic rules derived from NIST SP 800-52r2, RFC 8996, BSI TR-02102-2, and CERT-In CIAD-2020-04. "
        "The baseline rule score is calculated as <i>RuleScore = 100 − Σ rule_weights</i>. "
        "The machine learning layer computes a bounded negative adjustment: each anomalous session contributes at most "
        "2.0 points, scaled by the risk classifier's confidence in a malicious/deprecated class, capped at 10.0 points maximum across "
        "the scan. The AI can deepen a finding but never soften one or downgrade clean sessions. "
        "<br/><br/>"
        "<b>Audit Statement:</b> This audit was performed completely out-of-band via passive network packet capture inspection. "
        "No active probes, handshakes, or packets were transmitted to the evaluated hosts or networks."
    )
    appendix_box = Table(
        [[Paragraph(appendix_text, ParagraphStyle("App", fontName="Helvetica", fontSize=6.5, leading=8.5, textColor=SLATE_MUTED))]],
        colWidths=[pw],
    )
    appendix_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SURFACE_LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("PADDING", (0, 0), (-1, -1), 2.5 * mm),
    ]))
    story.append(KeepTogether([appendix_box]))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# HTML REPORT BUILDER
# ---------------------------------------------------------------------------
def build_html(result: dict, scan_name: str = "capture.pcap") -> bytes:
    """Generate an interactive, executive-grade HTML posture assessment report."""
    result = _normalize(result)
    ml_on, anomalies, risk_dist = _ml_sections_data(result)
    compliance = _compliance_table(result.get("findings", []))

    # Deduplicate certificates
    all_certs = result.get("certificates", [])
    unique_certs = []
    seen_fps = set()
    for c in all_certs:
        fp = c.get("fingerprint_sha256")
        if fp and fp not in seen_fps:
            seen_fps.add(fp)
            unique_certs.append(c)
        elif not fp:
            unique_certs.append(c)

    template = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Prahari Report — {{ name }}</title>
<style>
  :root {
    --bg: #2A232A;
    --surface: #3B353B;
    --card: #352E35;
    --border: #786C78;
    --text: #F8F6F8;
    --muted: #C4BCC4;
    --accent: #AD22FF;
    --primary: #6A2F8D;
    --crit: #FF7A6B;
    --crit-bg: rgba(255, 122, 107, 0.14);
    --high: #FFB25C;
    --high-bg: rgba(255, 178, 92, 0.14);
    --med: #FFE08A;
    --med-bg: rgba(255, 224, 138, 0.14);
    --low: #8FD0FF;
    --low-bg: rgba(143, 208, 255, 0.14);
    --ok: #7DE8B8;
    --ok-bg: rgba(125, 232, 184, 0.14);
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    margin: 0;
    padding: 32px 20px;
  }
  .container { max-width: 1100px; margin: 0 auto; }
  
  /* Hero Banner - Clean Light Hero matching website */
  .hero {
    background: #F8F6F8;
    border: 1px solid #D9D9D9;
    border-left: 4px solid #6A2F8D;
    border-radius: 10px;
    padding: 24px 28px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
  }
  .hero-tag {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.08em;
    color: #6A2F8D;
    text-transform: uppercase;
    margin-bottom: 6px;
  }
  .hero-title {
    font-size: 26px;
    font-weight: 800;
    margin: 0 0 4px;
    color: #1D161D;
    display: flex;
    align-items: baseline;
    gap: 8px;
  }
  .hero-title span { font-size: 16px; font-weight: 600; color: #6A2F8D; }
  .hero-sub { color: #564E56; font-size: 13px; margin: 0; }
  .hero-meta { text-align: right; }
  .hero-meta .file { font-size: 16px; font-weight: 700; color: #6A2F8D; margin-bottom: 4px; }
  .hero-meta .info { font-size: 12px; color: #786C78; }

  /* Dashboard Cards */
  .dashboard {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 20px;
  }
  .card-label {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin-bottom: 8px;
  }
  .grade-badge {
    font-size: 32px;
    font-weight: 900;
    line-height: 1;
    margin-bottom: 4px;
  }
  .grade-A, .grade-B { color: var(--ok); }
  .grade-C { color: var(--med); }
  .grade-D { color: var(--high); }
  .grade-F { color: var(--crit); }
  
  .score-num { font-size: 15px; font-weight: 600; }
  .stat-row { font-size: 13px; margin: 4px 0; color: #CBD5E1; }
  .stat-row b { color: #FFF; }
  
  /* Alert Box */
  .alert {
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 28px;
    border-left: 4px solid;
    font-size: 13.5px;
  }
  .alert-critical {
    background: var(--crit-bg);
    border-color: var(--crit);
    color: #FECACA;
  }
  .alert-critical b { color: #FFF; }
  .alert-ok {
    background: var(--ok-bg);
    border-color: var(--ok);
    color: #A7F3D0;
  }
  .alert-ok b { color: #FFF; }

  /* Section Styles */
  h2 {
    font-size: 18px;
    font-weight: 700;
    margin: 32px 0 6px;
    color: #FFF;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .sec-sub { font-size: 12.5px; color: var(--muted); margin-bottom: 14px; }
  
  /* Tables */
  table {
    width: 100%;
    border-collapse: collapse;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    margin-bottom: 24px;
    font-size: 13px;
  }
  th {
    background: #3A194D;
    color: #F8F6F8;
    text-align: left;
    padding: 10px 14px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 700;
    border-bottom: 1px solid var(--border);
  }
  td {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255, 255, 255, 0.04); }
  
  /* Badges & Monospace */
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px;
    color: #D8B4FE;
  }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
  }
  .badge-critical { background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit); }
  .badge-high { background: var(--high-bg); color: var(--high); border: 1px solid var(--high); }
  .badge-medium { background: var(--med-bg); color: var(--med); border: 1px solid var(--med); }
  .badge-low { background: var(--low-bg); color: var(--low); border: 1px solid var(--low); }
  .badge-info { background: rgba(196, 188, 196, 0.12); color: var(--muted); border: 1px solid var(--muted); }

  /* Appendix */
  .appendix {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    font-size: 12px;
    color: var(--muted);
    line-height: 1.6;
    margin-top: 40px;
  }
  .appendix b { color: #E2E8F0; }

  /* Print Stylesheet */
  @media print {
    :root {
      --bg: #FFFFFF;
      --surface: #F8F6F8;
      --card: #FFFFFF;
      --border: #D9D9D9;
      --text: #1D161D;
      --muted: #786C78;
      --accent: #6A2F8D;
      --crit: #DC2626;
      --crit-bg: #FEF2F2;
      --ok: #16A34A;
      --ok-bg: #F0FDF4;
    }
    body { background: #FFF; color: #1D161D; padding: 0; font-size: 11px; }
    .hero { background: #F8F6F8 !important; border: 1px solid #D9D9D9 !important; border-left: 4px solid #6A2F8D !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    h2 { color: #6A2F8D !important; }
    table { page-break-inside: auto; }
    tr { page-break-inside: avoid; page-break-after: auto; }
    .card { break-inside: avoid; }
    th { background: #3A194D !important; color: #FFFFFF !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .mono { color: #6A2F8D !important; }
  }
</style>
</head>
<body>
<div class="container">

  <!-- Header Banner -->
  <div class="hero">
    <div>
      <div class="hero-tag">Smart India Hackathon 2026 · NTRO (PS-26159)</div>
      <div class="hero-title">PRAHARI <span>| SECUREMAILSCOPE</span></div>
      <div class="hero-sub">Cryptographic Security Posture &amp; Forensic Assessment Report</div>
    </div>
    <div class="hero-meta">
      <div class="file">{{ name }}</div>
      <div class="info">{{ generated_at }}</div>
      <div class="info">Standards: NIST SP 800-52r2 · BSI · CERT-In</div>
    </div>
  </div>

  <!-- Scorecard Dashboard -->
  <div class="dashboard">
    <div class="card" style="border-color: var(--{{ 'ok' if score >= 80 else ('med' if score >= 60 else 'crit') }});">
      <div class="card-label">Overall Posture</div>
      <div class="grade-badge grade-{{ grade }}">GRADE {{ grade }}</div>
      <div class="score-num"><span class="grade-{{ grade }}">{{ score }}</span> / 100</div>
      <div style="font-size:11px; color:var(--muted); margin-top:6px;">
        {{ 'Strong Posture · NIST Compliant' if score >= 80 else ('Elevated Risk · Deprecated Suites' if score >= 50 else 'Critical Exposure · Action Required') }}
      </div>
    </div>

    <div class="card">
      <div class="card-label">Score Fusion Engine</div>
      <div class="stat-row">Rule score: <b>{{ rule_score }}/100</b></div>
      <div class="stat-row">AI adjustment: <b style="color:var(--crit);">&minus;{{ ml_adjustment }} pts</b></div>
      <div class="stat-row">Final score: <b class="grade-{{ grade }}">{{ score }}/100</b></div>
      <div style="font-size:11px; color:var(--muted); margin-top:6px;">
        Score = clamp(Rule &minus; Adj, 0, 100)
      </div>
    </div>

    <div class="card">
      <div class="card-label">Findings Breakdown</div>
      <div class="stat-row">
        <span style="color:var(--crit)">● <b>{{ severity_counts.critical or 0 }} Critical</b></span> &nbsp;
        <span style="color:var(--high)">● <b>{{ severity_counts.high or 0 }} High</b></span>
      </div>
      <div class="stat-row">
        <span style="color:var(--med)">● <b>{{ severity_counts.medium or 0 }} Medium</b></span> &nbsp;
        <span style="color:var(--low)">● <b>{{ severity_counts.low or 0 }} Low</b></span>
      </div>
      <div class="stat-row">
        <span style="color:var(--muted)">● <b>{{ severity_counts.info or 0 }} Informational</b></span>
      </div>
    </div>

    <div class="card">
      <div class="card-label">Scope &amp; Telemetry</div>
      <div class="stat-row">Sessions: <b>{{ session_count }}</b> reconstructed</div>
      <div class="stat-row">Protocols: <b>{{ protocols or 'None' }}</b></div>
      <div class="stat-row">Certificates: <b>{{ certificate_count }}</b> observed</div>
      <div style="font-size:11px; color:var(--muted); margin-top:6px;">
        Passive out-of-band wire capture
      </div>
    </div>
  </div>

  <!-- Executive Alert Callout -->
  {% if severity_counts.critical or severity_counts.high %}
  <div class="alert alert-critical">
    <b>[!] CRITICAL SECURITY EXPOSURES IDENTIFIED:</b>
    Cleartext credentials or deprecated cryptography were observed on the wire.
    Passive adversaries can intercept mail communications or authentication credentials without active MITM.
  </div>
  {% else %}
  <div class="alert alert-ok">
    <b>[✓] CRYPTOGRAPHIC POSTURE SATISFIED:</b>
    All analyzed sessions comply with NIST SP 800-52r2 cryptographic baseline standards.
  </div>
  {% endif %}

  <!-- 1. Findings -->
  <h2>1. Security Findings &amp; Deficiencies</h2>
  <div class="sec-sub">Deterministic violations mapped to national and international security standards.</div>
  {% if findings %}
    {% for sev, items in findings.items() %}
    <div style="margin-bottom: 16px;">
      <span class="badge badge-{{ sev }}">{{ sev | upper }} ({{ items | length }})</span>
      <table>
        <thead>
          <tr>
            <th style="width:14%">Session</th>
            <th style="width:38%">Deficiency &amp; Technical Risk</th>
            <th style="width:24%">Standard Reference</th>
            <th style="width:24%">Remediation Guidance</th>
          </tr>
        </thead>
        <tbody>
        {% for f in items %}
        <tr>
          <td class="mono"><b>{{ f.session_id or 'Global' }}</b></td>
          <td>
            <b>{{ f.title }}</b><br>
            <span style="color:var(--muted); font-size:12px;">{{ f.description }}</span>
          </td>
          <td style="color:#CBD5E1; font-size:12px;">{{ f.reference }}</td>
          <td style="font-size:12px;">{{ f.remediation }}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
    {% endfor %}
  {% else %}
    <div class="card" style="color:var(--ok); font-weight:600;">No findings — all sessions passed every evaluated rule.</div>
  {% endif %}

  <!-- Advisories -->
  {% if advisories %}
  <h2>Cryptographic Advisories (Status Quo Signals)</h2>
  <div class="sec-sub">Informational transition markers (e.g. quantum transition status) with zero score weight.</div>
  <table>
    <thead>
      <tr>
        <th style="width:14%">Session</th>
        <th style="width:46%">Advisory Title &amp; Context</th>
        <th style="width:40%">Migration Guidance</th>
      </tr>
    </thead>
    <tbody>
    {% for a in advisories %}
    <tr>
      <td class="mono"><b>{{ a.session_id or '—' }}</b></td>
      <td><b>{{ a.title }}</b><br><span style="color:var(--muted); font-size:12px;">{{ a.description }}</span></td>
      <td style="font-size:12px;">{{ a.remediation }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <!-- 2. Reconstructed Sessions -->
  <h2>2. Reconstructed Session Inventory</h2>
  <div class="sec-sub">Wire telemetry extracted through stream reassembly and protocol parsing.</div>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Protocol</th>
        <th>Transport</th>
        <th>TLS</th>
        <th>Cipher Suite</th>
        <th>PFS</th>
        <th>Grade</th>
        <th>ML Risk</th>
      </tr>
    </thead>
    <tbody>
    {% for s in sessions %}
    <tr>
      <td class="mono"><b>{{ s.session_id }}</b></td>
      <td><b>{{ s.protocol | upper }}</b></td>
      <td>{{ s.transport }}</td>
      <td><b>{{ s.tls_version or '—' }}</b></td>
      <td class="mono" style="font-size:11.5px;">{{ s.cipher_suite or '—' }}</td>
      <td>
        <span style="color:{{ 'var(--ok)' if s.pfs else ('var(--crit)' if s.pfs == false else 'var(--muted)') }}">
          {{ 'Yes' if s.pfs else ('No' if s.pfs == false else '—') }}
        </span>
      </td>
      <td><b class="grade-{{ s.grade }}">{{ s.grade }} ({{ s.risk_score }})</b></td>
      <td>
        {% if s.ml_risk %}
        <span class="badge badge-{{ 'critical' if s.ml_risk.label in ['critical', 'high'] else 'ok' }}">{{ s.ml_risk.label }}</span>
        {% else %}—{% endif %}
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <!-- 3. AI Anomaly Analysis -->
  <h2>3. AI Anomaly &amp; Statistical Threat Analysis</h2>
  <div class="sec-sub">Isolation Forest model deviations against learned baseline traffic distributions.</div>
  {% if not ml_enabled %}
    <div class="card" style="color:var(--muted);">The AI ML layer was disabled for this scan. Rule evaluation is fully active.</div>
  {% elif anomalies %}
    <table>
      <thead>
        <tr>
          <th style="width:14%">Session</th>
          <th style="width:14%">Anomaly Score</th>
          <th style="width:16%">Risk Class</th>
          <th style="width:56%">Feature Deviation (|z| &gt; 2 indicates significant outlier)</th>
        </tr>
      </thead>
      <tbody>
      {% for a in anomalies %}
      <tr>
        <td class="mono"><b>{{ a.session_id }}</b></td>
        <td><b style="color:var(--crit)">{{ a.score }}</b></td>
        <td><b>{{ (a.ml_risk.label if a.ml_risk else '—') }}</b></td>
        <td style="font-size:12px;">
          {% for t in a.top_features %}
            <span class="mono">{{ t.feature.replace('_', ' ') }}</span> at <b>{{ t.z }}&sigma;</b> (val {{ t.value }}){{ ', ' if not loop.last else '' }}
          {% endfor %}
        </td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  {% else %}
    <div class="card" style="color:var(--ok); font-weight:600;">
      No anomalies — every reconstructed session conforms to the healthy operational baseline.
    </div>
  {% endif %}

  <!-- 4. Certificates -->
  <h2>4. X.509 Certificate Inventory</h2>
  <div class="sec-sub">Cryptographic parameter verification for observed public key certificates.</div>
  {% if certificates %}
  <table>
    <thead>
      <tr>
        <th>Subject Common Name</th>
        <th>Key &amp; Algorithm</th>
        <th>Signature</th>
        <th>Validity</th>
        <th>SHA-256 Fingerprint</th>
      </tr>
    </thead>
    <tbody>
    {% for c in certificates %}
    <tr>
      <td><b>{{ c.subject_cn }}</b></td>
      <td>{{ c.key_algorithm }} {{ c.key_length }}b</td>
      <td>{{ c.signature_hash }}</td>
      <td>
        {{ c.not_after[:10] }}
        {% if c.is_expired %}<br><b style="color:var(--crit)">[EXPIRED]</b>{% endif %}
      </td>
      <td class="mono" style="font-size:11px;">{{ c.fingerprint_sha256[:28] }}&hellip;</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="card" style="color:var(--muted);">No X.509 certificates observed in this traffic capture.</div>
  {% endif %}

  <!-- 5. Compliance Matrix -->
  <h2>5. Compliance mapping &amp; Regulatory Standards Matrix</h2>
  <div class="sec-sub">Cross-reference of findings to NIST SP 800-52r2, RFC 8996, BSI TR-02102, and CERT-In CIAD-2020-04.</div>
  {% if compliance %}
  <table>
    <thead>
      <tr>
        <th style="width:44%">Regulatory Standard &amp; Clause</th>
        <th style="width:14%">Rule ID</th>
        <th style="width:26%">Requirement Description</th>
        <th style="width:10%">Severity</th>
        <th style="width:6%">Count</th>
      </tr>
    </thead>
    <tbody>
    {% for ref, rid, title, sev, n in compliance %}
    <tr>
      <td class="mono" style="color:#FFF;"><b>{{ ref }}</b></td>
      <td class="mono">{{ rid }}</td>
      <td>{{ title }}</td>
      <td><span class="badge badge-{{ sev }}">{{ sev }}</span></td>
      <td><b>{{ n }}</b></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="card" style="color:var(--ok); font-weight:600;">All compliance baselines satisfied.</div>
  {% endif %}

  <!-- Appendix -->
  <div class="appendix">
    <b>Methodology &amp; Mathematical Scoring Formula:</b> The deterministic rule engine evaluates 25 cryptographic rules mapped to NIST SP 800-52r2, RFC 8996, BSI TR-02102-2, and CERT-In CIAD-2020-04. Baseline score is computed as <i>RuleScore = 100 &minus; &Sigma; rule_weights</i>. The machine learning layer computes a bounded negative adjustment: each session contributes at most 2.0 points, scaled by the risk classifier confidence in an insecure class, capped at 10.0 points total across the scan. Fused score is clamped to [0, 100].
    <br><br>
    <b>Audit Statement:</b> Generated by {{ product_line }}. This assessment was conducted passively via PCAP deep packet inspection with zero active network probing.
  </div>

</div>
</body>
</html>""")

    p = result.get("posture", {})
    proto_items = [f"{k.upper()} ({v})" for k, v in sorted(result.get("protocol_counts", {}).items())]
    protocols_str = ", ".join(proto_items)

    html = template.render(
        name=scan_name,
        product_line=PRODUCT_LINE,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        score=p.get("score", 0),
        grade=p.get("grade", "—"),
        rule_score=p.get("rule_score", p.get("score", 0)),
        ml_adjustment=p.get("ml_adjustment", 0),
        severity_counts=p.get("severity_counts", {}),
        session_count=len(result.get("sessions", [])),
        certificate_count=len(unique_certs),
        protocols=protocols_str,
        summary=_summary_text(result),
        findings=_grouped_findings(result),
        advisories=result.get("advisories", []),
        sessions=result.get("sessions", []),
        certificates=unique_certs,
        ml_enabled=ml_on,
        anomalies=anomalies,
        risk_dist=risk_dist,
        compliance=compliance,
    )
    return html.encode("utf-8")
