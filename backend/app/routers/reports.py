"""Report export endpoints (JSON / HTML / PDF) + misc public routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response

from ..deps import store
from ..ml_runtime.predict import model_info
from ..reports.builder import build_html, build_json, build_pdf

router = APIRouter(prefix="/api", tags=["reports"])


def _result(scan_id: str) -> dict:
    result = store().get_result(scan_id)
    scan = store().get_scan(scan_id)
    if not scan or result is None:
        raise HTTPException(404, "report not available")
    return scan, result


@router.get("/scans/{scan_id}/report.json")
def report_json(scan_id: str):
    scan, result = _result(scan_id)
    data = build_json(result)
    return Response(data, media_type="application/json",
                    headers={"Content-Disposition":
                             'attachment; filename="scan-%s-report.json"' % scan_id[:8]})


@router.get("/scans/{scan_id}/report.html")
def report_html(scan_id: str):
    scan, result = _result(scan_id)
    data = build_html(result, scan["name"])
    return Response(data, media_type="text/html",
                    headers={"Content-Disposition":
                             'inline; filename="scan-%s-report.html"' % scan_id[:8]})


@router.get("/scans/{scan_id}/report.pdf")
def report_pdf(scan_id: str):
    scan, result = _result(scan_id)
    data = build_pdf(result, scan["name"])
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition":
                             'attachment; filename="scan-%s-report.pdf"' % scan_id[:8]})


@router.get("/model")
def model_card():
    """Published model metrics for the UI model card.
    metrics.json is the authority: served flat so the UI reads
    risk_classifier/anomaly_detector with their full fields. Falls back to
    the bundle summary when the metrics file is absent."""
    info = model_info()
    metrics = info.pop("metrics", None)
    if metrics:
        return metrics
    return info


@router.get("/stats")
def public_stats():
    """Landing-page counters — real numbers only (0 until scans exist)."""
    s = store()
    sessions = 0
    findings = 0
    try:
        s.list_scans(100, 0)          # fills the read-through cache from the DB
    except Exception:
        pass
    for scan in list(getattr(s, "scans", {}).values()):
        result = s.get_result(scan["id"])
        if result:
            sessions += len(result.get("sessions", []))
            findings += len(result.get("findings", []))
    return {"scans": len(getattr(s, "scans", {})), "sessions": sessions,
            "findings": findings, "ml": model_info()}
