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

from jinja2 import Template
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

HERE = os.path.dirname(os.path.abspath(__file__))

PRODUCT = "Prahari"
PRODUCT_LINE = "Prahari — SecureMailScope · AI-Assisted Cryptographic Security Posture Assessment"
SCHEMA = "prahari.report/v1"
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


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
    for f in result["findings"]:
        out.setdefault(f["severity"], []).append(f)
    for sev in out:
        out[sev].sort(key=lambda f: (f["session_id"] is None, f["session_id"] or ""))
    return {s: out[s] for s in SEV_ORDER if s in out}


def _compliance_table(findings: list[dict]) -> list[tuple[str, str, str, str, int]]:
    """Group findings by standard reference -> (reference, clause, rule, severity, count)."""
    rows: dict[tuple, tuple[str, str, str, str, int]] = {}
    order: list[tuple] = []
    for f in findings:
        ref = f.get("reference") or "—"
        # first sentence fragment before ';' or '(' is the standard clause
        clause = ref.split(";")[0].strip()
        standard = clause.split("§")[0].strip() if "§" in clause else \
            (clause.split(" ")[0] if clause and clause[0].isupper() else clause)
        key = (ref, f["rule_id"])
        if key not in rows:
            rows[key] = (ref, f["rule_id"], f["title"], f["severity"], 1)
            order.append(key)
        else:
            r = rows[key]
            rows[key] = (r[0], r[1], r[2], r[3], r[4] + 1)
    return [rows[k] for k in order]


def _summary_text(result: dict) -> str:
    p = result["posture"]
    n_sess = len(result["sessions"])
    sev = p["severity_counts"]
    worst = ", ".join("%d %s" % (sev[s], s) for s in SEV_ORDER if sev.get(s)) or "none"
    weak_protos = [k for k, v in result["protocol_counts"].items()
                   if k in ("smtp", "imap", "pop3")]
    lines = [
        "The analyzed capture contains %d reconstructed email session(s). "
        "The deterministic rule engine scored the cryptographic posture %d/100"
        % (n_sess, p.get("rule_score", p["score"])),
    ]
    if p.get("ml_adjustment"):
        lines[-1] += (" and the AI layer adjusted it by −%s to a fused score "
                     "of %d/100 (grade %s)"
                     % (p["ml_adjustment"], p["score"], p["grade"]))
    else:
        lines[-1] += " (grade %s)" % p["grade"]
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
    p = result["posture"]
    ml = p.get("ml") or {}
    return bool(ml.get("enabled")), result.get("anomaly_explanations", []), \
        ml.get("risk_distribution") or {}


def build_html(result: dict, scan_name: str = "capture.pcap") -> bytes:
    result = _normalize(result)
    ml_on, anomalies, risk_dist = _ml_sections_data(result)
    compliance = _compliance_table(result["findings"])
    template = Template("""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Prahari report — {{ name }}</title>
<style>
 :root { color-scheme: dark; }
 body { font: 16px/1.6 system-ui, sans-serif; background: #191b22; color: #e7e9ee;
        max-width: 960px; margin: 0 auto; padding: 40px 20px; }
 h1 { font-size: 1.9rem; margin: 0 0 4px; } h2 { margin-top: 40px; }
 .score { font-size: 3.4rem; font-weight: 700; }
 .grade-A,.grade-B{color:#4ade80}.grade-C,.grade-D{color:#fbbf24}.grade-F{color:#f87171}
 table { border-collapse: collapse; width: 100%; margin: 16px 0; font-size: 14px; }
 th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #333845; }
 th { color: #9aa3b2; font-weight: 600; font-size: 12px; text-transform: uppercase;
      letter-spacing: .06em; }
 code, .mono { font-family: ui-monospace, monospace; font-size: 12.5px; color: #a5f3fc; }
 .sev-critical{color:#f87171;font-weight:700}.sev-high{color:#fb923c;font-weight:600}
 .sev-medium{color:#fbbf24}.sev-low{color:#7dd3fc}.sev-info{color:#9aa3b2}
 .muted{color:#9aa3b2}
 .fusion span { display:inline-block; margin-right: 18px; }
</style></head><body>
<h1>Prahari — Cryptographic Security Posture Report</h1>
<p class="muted">SecureMailScope · AI-Assisted Cryptographic Security Posture Assessment<br>
{{ name }} · generated {{ generated_at }}</p>
<p><span class="score grade-{{ grade }}">{{ score }}/100</span><br>
   Grade <b class="grade-{{ grade }}">{{ grade }}</b> · {{ session_count }} session(s)</p>
<p class="fusion muted">
<span>rule score: <b>{{ rule_score }}</b></span>
<span>AI adjustment: <b>−{{ ml_adjustment }}</b></span>
<span>fused: <b>{{ score }}/100</b></span></p>
<h2>Executive summary</h2><p>{{ summary }}</p>
<h2>Findings</h2>
{% for sev, items in findings.items() %}
  <h3 class="sev-{{ sev }}">{{ sev | upper }} ({{ items | length }})</h3>
  <table><tr><th>Session</th><th>Finding</th><th>Reference</th><th>Fix</th></tr>
  {% for f in items %}
  <tr><td class="mono">{{ f.session_id }}</td>
      <td><b>{{ f.title }}</b><br><span class="muted">{{ f.description }}</span></td>
      <td>{{ f.reference }}</td><td>{{ f.remediation }}</td></tr>
  {% endfor %}</table>
  {% else %}<p>No findings — all analyzed sessions passed every rule.</p>{% endfor %}
{% if advisories %}
<h2>Advisories (informational — not scored)</h2>
<p class="muted">Posture signals that are the current industry status quo rather than
misconfiguration, reported for migration planning. They carry zero weight and never change
the score.</p>
<table><tr><th>Session</th><th>Advisory</th><th>Detail</th><th>Guidance</th></tr>
{% for a in advisories %}
<tr><td class="mono">{{ a.session_id }}</td>
    <td><b>{{ a.title }}</b></td>
    <td class="muted">{{ a.description }}</td><td>{{ a.remediation }}</td></tr>
{% endfor %}</table>
{% endif %}
<h2>Sessions</h2>
<table><tr><th>ID</th><th>Proto</th><th>Transport</th><th>TLS</th><th>Cipher</th>
<th>PFS</th><th>Grade</th><th>ML risk</th><th>Anomaly</th></tr>
{% for s in sessions %}
<tr><td class="mono">{{ s.session_id }}</td><td>{{ s.protocol }}</td>
    <td>{{ s.transport }}</td><td>{{ s.tls_version or "—" }}</td>
    <td class="mono">{{ (s.cipher_suite or "—")[:44] }}</td>
    <td>{{ "yes" if s.pfs else ("no" if s.pfs == false else "—") }}</td>
    <td class="grade-{{ s.grade }}">{{ s.grade }} ({{ s.risk_score }})</td>
    <td>{{ (s.ml_risk.label if s.ml_risk else "—") }}</td>
    <td>{{ "flagged" if s.is_anomaly else "" }}</td></tr>
{% endfor %}</table>
<h2>AI anomaly analysis</h2>
{% if not ml_enabled %}<p class="muted">The AI layer was not available for this scan
(rule engine results are unaffected).</p>
{% elif anomalies %}
<p class="muted">Sessions the IsolationForest flagged as deviating from the healthy
baseline. Z-scores describe how many standard deviations each feature sits from
the training baseline; |z| &gt; 2 is a strong deviation.</p>
{% for a in anomalies %}
<p><b class="mono">{{ a.session_id }}</b> — anomaly score {{ a.score }}{% if a.ml_risk %},
risk class {{ a.ml_risk.label }}{% endif %}:
{% for t in a.top_features %}{{ t.feature.replace("_", " ") }} at {{ t.z }}σ
(value {{ t.value }}){{ ", " if not loop.last else "." }}{% endfor %}</p>
{% endfor %}
{% else %}<p>No anomalies — every reconstructed session matches the healthy baseline
learned from the training corpus.</p>{% endif %}
<h2>Certificates</h2>
<table><tr><th>Subject</th><th>Issuer</th><th>Key</th><th>Signature</th>
<th>Valid until</th><th>SHA-256</th></tr>
{% for c in certificates %}
<tr><td>{{ c.subject_cn }}</td><td>{{ c.issuer_cn }}</td>
    <td>{{ c.key_algorithm }} {{ c.key_length }}b</td><td>{{ c.signature_hash }}</td>
    <td>{{ c.not_after[:10] }}{{ " (expired)" if c.is_expired }}</td>
    <td class="mono">{{ c.fingerprint_sha256[:24] }}…</td></tr>
{% else %}<p class="muted">No certificates observed.</p>{% endfor %}</table>
<h2>Compliance mapping</h2>
<p class="muted">Every finding mapped to its standard reference. Clause text is quoted
from the rule engine's mapping (NIST SP 800-52r2 / RFC 8996 / BSI TR-02102 /
CERT-In guidance; PQC findings cite FIPS 203/204/205).</p>
<table><tr><th>Reference (standard · clause)</th><th>Rule</th><th>Finding</th><th>Severity</th><th>Count</th></tr>
{% for ref, rid, title, sev, n in compliance %}
<tr><td class="mono">{{ ref }}</td><td class="mono">{{ rid }}</td>
    <td>{{ title }}</td><td class="sev-{{ sev }}">{{ sev }}</td><td>{{ n }}</td></tr>
{% else %}<tr><td colspan="5">No findings — nothing to map.</td></tr>{% endfor %}</table>
<h2>Method — how the AI changes the score</h2>
<p class="muted">The rule engine alone produces the <b>rule score</b>
(100 − Σ rule weights, mapped to NIST SP 800-52r2 / RFC 8996 / BSI TR-02102 /
CERT-In). The AI layer may then apply a <b>bounded negative adjustment</b>:
each session contributes at most 2 points, the scan total at most 10, driven by
(anomaly flag × classifier confidence in a bad risk class). The AI can deepen
a verdict the rules already imply but never soften one, never raises a clean
session above its rule score, and a clean capture stays exactly 100/A.</p>
{% if risk_dist %}<p class="muted">Risk-class distribution across sessions:
{% for k, v in risk_dist.items() %}{{ k }} {{ v }}{{ ", " if not loop.last }}{% endfor %}.</p>{% endif %}
<p class="muted">Generated by {{ product_line }} · passive PCAP analysis ·
rules mapped to NIST SP 800-52r2 / BSI TR-02102 / CERT-In guidance.</p>
</body></html>""")
    html = template.render(
        name=scan_name, product_line=PRODUCT_LINE,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        score=result["posture"]["score"], grade=result["posture"]["grade"],
        rule_score=result["posture"].get("rule_score", result["posture"]["score"]),
        ml_adjustment=result["posture"].get("ml_adjustment", 0),
        session_count=len(result["sessions"]),
        summary=_summary_text(result),
        findings=_grouped_findings(result),
        advisories=result.get("advisories", []),
        sessions=result["sessions"],
        certificates=result["certificates"],
        ml_enabled=ml_on, anomalies=anomalies, risk_dist=risk_dist,
        compliance=compliance,
    )
    return html.encode()


def build_pdf(result: dict, scan_name: str = "capture.pcap") -> bytes:
    result = _normalize(result)
    ml_on, anomalies, risk_dist = _ml_sections_data(result)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="Prahari Report")
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Title"], fontSize=22)
    sevc = {"critical": colors.HexColor("#b91c1c"), "high": colors.HexColor("#c2410c"),
            "medium": colors.HexColor("#a16207"), "low": colors.HexColor("#0369a1"),
            "info": colors.HexColor("#4b5563")}
    story = [
        Paragraph("Prahari", h1),
        Paragraph("SecureMailScope · AI-Assisted Cryptographic Security "
                  "Posture Assessment — %s" % scan_name, styles["Normal"]),
        Spacer(1, 8 * mm),
        Paragraph("Posture score: <b>%d/100</b> — grade <b>%s</b> · %d session(s)"
                  % (result["posture"]["score"], result["posture"]["grade"],
                     len(result["sessions"])), styles["Heading2"]),
        Paragraph("Rule score %d · AI adjustment −%s · fused %d/100"
                  % (result["posture"].get("rule_score", result["posture"]["score"]),
                     result["posture"].get("ml_adjustment", 0),
                     result["posture"]["score"]), styles["Normal"]),
        Paragraph(_summary_text(result).replace("\n\n", "<br/><br/>"),
                  styles["Normal"]),
        PageBreak(),
        Paragraph("Findings", styles["Heading1"]),
    ]
    grouped = _grouped_findings(result)
    if not grouped:
        story.append(Paragraph("No findings — all sessions passed every rule.",
                               styles["Normal"]))
    for sev, items in grouped.items():
        story.append(Paragraph("%s (%d)" % (sev.upper(), len(items)),
                               ParagraphStyle("S", parent=styles["Heading2"],
                                              textColor=sevc[sev])))
        rows = [["Session", "Finding", "Reference"]]
        for f in items:
            rows.append([f["session_id"], f["title"], f["reference"]])
        t = Table(rows, colWidths=[28 * mm, 95 * mm, 47 * mm])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story += [t, Spacer(1, 5 * mm)]
    advisories = result.get("advisories", [])
    if advisories:
        story.append(Paragraph(
            "Advisories (informational — not scored)",
            ParagraphStyle("S", parent=styles["Heading2"],
                           textColor=sevc["info"])))
        story.append(Paragraph(
            "Posture signals that are the current industry status quo rather than "
            "misconfiguration, reported for migration planning. They carry zero "
            "weight and never change the score.", styles["Normal"]))
        rows = [["Session", "Advisory", "Guidance"]]
        for a in advisories:
            rows.append([a["session_id"], a["title"], a["remediation"]])
        t = Table(rows, colWidths=[28 * mm, 95 * mm, 47 * mm])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story += [t, Spacer(1, 5 * mm)]
    story.append(PageBreak())
    story.append(Paragraph("Session inventory", styles["Heading1"]))
    rows = [["ID", "Proto", "Transport", "TLS", "Cipher", "Grade", "ML"]]
    for s in result["sessions"]:
        rows.append([s["session_id"], s["protocol"], s["transport"],
                     s["tls_version"] or "—", (s["cipher_suite"] or "—")[:34],
                     "%s (%d)" % (s["grade"], s["risk_score"]),
                     (s.get("ml_risk") or {}).get("label", "—")])
    t = Table(rows, colWidths=[20 * mm, 14 * mm, 20 * mm, 17 * mm, 74 * mm,
                               22 * mm, 18 * mm])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
    ]))
    story += [t, Spacer(1, 5 * mm)]

    story.append(Paragraph("AI anomaly analysis", styles["Heading1"]))
    if not ml_on:
        story.append(Paragraph("The AI layer was not available for this scan; "
                               "rule-engine results are unaffected.", styles["Normal"]))
    elif anomalies:
        for a in anomalies:
            feats = ", ".join("%s at %sσ (value %s)" %
                              (x["feature"].replace("_", " "), x["z"], x["value"])
                              for x in a["top_features"])
            story.append(Paragraph(
                "<b>%s</b> — anomaly score %s, risk class %s: %s."
                % (a["session_id"], a["score"],
                   (a.get("ml_risk") or {}).get("label", "—"), feats),
                styles["Normal"]))
    else:
        story.append(Paragraph("No anomalies — every reconstructed session "
                               "matches the healthy baseline learned from the "
                               "training corpus.", styles["Normal"]))
    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("Certificate inventory", styles["Heading1"]))
    rows = [["Subject", "Key", "Signature", "Expires", "SHA-256 (truncated)"]]
    for c in result["certificates"]:
        rows.append([c["subject_cn"], "%s %db" % (c["key_algorithm"], c["key_length"]),
                     c["signature_hash"], c["not_after"][:10] +
                     (" (EXPIRED)" if c["is_expired"] else ""),
                     c["fingerprint_sha256"][:24]])
    if len(rows) > 1:
        t = Table(rows, colWidths=[38 * mm, 22 * mm, 24 * mm, 34 * mm, 62 * mm])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ]))
        story.append(t)
    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph("Compliance mapping", styles["Heading1"]))
    comp = _compliance_table(result["findings"])
    rows = [["Reference (standard · clause)", "Rule", "Severity", "Count"]]
    for ref, rid, title, sev, n in comp:
        rows.append([ref, rid, sev, n])
    t = Table(rows, colWidths=[100 * mm, 26 * mm, 24 * mm, 16 * mm])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story += [t, Spacer(1, 8 * mm)]

    story.append(Paragraph(
        "Method — how the AI changes the score: the rule engine alone produces the "
        "rule score (100 − Σ rule weights; NIST SP 800-52r2 / RFC 8996 / BSI "
        "TR-02102 / CERT-In). The AI layer may apply a bounded negative adjustment "
        "(≤2 points per session, ≤10 per scan, anomaly flag × classifier confidence). "
        "It can deepen a verdict the rules already imply, never soften one, and a "
        "clean capture stays exactly 100/A.", styles["Normal"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "Generated by %s — passive analysis, no active probing."
        % PRODUCT_LINE, styles["Italic"]))
    doc.build(story)
    return buf.getvalue()
