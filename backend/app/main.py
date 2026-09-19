"""Prahari — AI-assisted cryptographic security posture assessment for
email traffic. FastAPI application entry point."""
from __future__ import annotations

import time

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .routers import reports, scans

app = FastAPI(title=settings.app_name, version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)
app.include_router(reports.router)


@app.get("/api/health")
def health():
    """Uptime probe (keep-alive pings via cron-job.org every ~10 min keep
    the Render free instance warm and the Supabase project active — see
    DEPLOY.md). Touches the store so a degraded DB shows up here."""
    db = "ok"
    try:
        from .deps import store
        store().list_scans(1, 0)
    except Exception:
        db = "degraded"
    return {"status": "ok", "db": db, "ts": time.time()}


@app.get("/")
def root():
    return {"service": "prahari-api",
            "product": "Prahari — AI-Assisted Cryptographic Security "
                       "Posture Assessment",
            "docs": "/docs"}
