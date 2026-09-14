"""Shared dependencies: store singleton, bounded analysis executor."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

from .config import settings
from .db.client import get_store

_store = None
_executor: ThreadPoolExecutor | None = None
_semaphore = asyncio.Semaphore(settings.max_concurrent_analyses)
_tasks: dict[str, dict] = {}          # scan_id -> {"future": Future}


def store():
    global _store
    if _store is None:
        _store = get_store()
    return _store


def executor() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=settings.max_concurrent_analyses,
                                       thread_name_prefix="analysis")
    return _executor


def tasks() -> dict:
    return _tasks


def analysis_slot() -> asyncio.Semaphore:
    """In-process admission control for analyses (free-tier RAM guard)."""
    return _semaphore
