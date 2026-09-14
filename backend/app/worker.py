"""Background analysis worker: runs the pipeline on the executor thread and
drives scan status/progress updates through the store.

Free-tier guards: the in-process semaphore caps simultaneous analyses so a
burst of uploads cannot self-DoS the 512 MB Render instance; the executor
itself is bounded to the same width. /analyze returns 202 immediately — all
work happens on the worker thread."""
from __future__ import annotations

import asyncio
import traceback

from .deps import executor, store, analysis_slot


def _run_sync(scan_id: str, data: bytes) -> None:
    from .pipeline.runner import analyze_pcap, result_to_dict

    def progress(pct: int, stage: str) -> None:
        store().update_scan(scan_id, progress=int(pct))

    try:
        from datetime import datetime, timezone
        store().update_scan(scan_id, status="parsing",
                            started_at=datetime.now(timezone.utc).isoformat())
        result = analyze_pcap(data, progress=progress)
        res = result_to_dict(result)
        store().put_result(scan_id, res)
        store().update_scan(
            scan_id,
            status="complete", progress=100,
            posture_score=res["posture"]["score"],
            grade=res["posture"]["grade"],
            protocol_counts=res["protocol_counts"],
            session_count=len(res["sessions"]),
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
        # free the big intermediates eagerly; the result dict is all we keep
        del result
    except Exception as exc:                       # pragma: no cover
        traceback.print_exc()
        store().update_scan(scan_id, status="failed", error=str(exc)[:500])


async def start_analysis(scan_id: str, data: bytes) -> None:
    loop = asyncio.get_running_loop()
    sem = analysis_slot()
    await sem.acquire()
    try:
        loop.run_in_executor(executor(), _release_and_run, sem, scan_id, data)
    except Exception:
        sem.release()
        raise


def _release_and_run(sem, scan_id: str, data: bytes) -> None:
    try:
        _run_sync(scan_id, data)
    finally:
        sem.release()
