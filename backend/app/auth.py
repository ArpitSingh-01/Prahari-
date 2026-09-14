"""Request auth: Supabase JWT verification with a documented dev fallback.

- With SUPABASE_URL set: verifies RS256 JWTs against Supabase's published
  JWKS (HS256+secret fallback when configured).
- Without it (local dev / CI): accepts `Authorization: Bearer dev-<anything>`
  and treats the token as the user id. Never enabled in production because
  SUPABASE_URL is always set there.
"""
from __future__ import annotations

import time

import httpx
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import settings

_bearer = HTTPBearer(auto_error=False)
_jwks_cache: dict = {"keys": None, "fetched_at": 0.0}


def _jwks() -> dict | None:
    now = time.time()
    if _jwks_cache["keys"] is not None and now - _jwks_cache["fetched_at"] < 3600:
        return _jwks_cache["keys"]
    try:
        url = settings.supabase_url.rstrip("/") + "/auth/v1/.well-known/jwks.json"
        resp = httpx.get(url, timeout=10)
        resp.raise_for_status()
        _jwks_cache["keys"] = resp.json()
        _jwks_cache["fetched_at"] = now
        return _jwks_cache["keys"]
    except Exception:
        return None


def _verify_supabase_jwt(token: str) -> tuple[str, str] | None:
    """Returns (user_id, role) from a verified Supabase JWT, or None."""
    try:
        import jwt
        from jwt import PyJWK
    except ImportError:
        return None
    kid = None
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        alg = header.get("alg", "RS256")
    except Exception:
        return None
    if alg == "HS256" and settings.supabase_jwt_secret:
        try:
            payload = jwt.decode(token, settings.supabase_jwt_secret,
                                 algorithms=["HS256"],
                                 options={"verify_aud": False})
            return payload.get("sub"), payload.get("role", "analyst")
        except Exception:
            return None
    keys = _jwks() or {}
    for key in keys.get("keys", []):
        if key.get("kid") == kid:
            try:
                payload = jwt.decode(token, PyJWK(key).key,
                                     algorithms=[alg],
                                     options={"verify_aud": False})
                return payload.get("sub"), payload.get("role", "analyst")
            except Exception:
                return None
    return None


async def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    if creds is None or not creds.credentials:
        raise HTTPException(401, "missing bearer token")
    token = creds.credentials
    if settings.supabase_url:
        verified = _verify_supabase_jwt(token)
        if not verified:
            raise HTTPException(401, "invalid or expired token")
        return verified[0]
    # local dev / test mode
    if token.startswith("dev-") and len(token) > 4:
        return token[4:]
    raise HTTPException(401, "invalid token (local mode expects 'dev-<user>')")


async def get_current_role(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    """Role claim from the JWT. Supabase JWTs carry a custom `role` claim
    when provisioned; it defaults to 'analyst' when absent — NEVER to
    admin. Local mode maps dev tokens explicitly: only dev-admin tokens
    (i.e. `dev-admin`) are admins; every other dev user is an analyst."""
    if creds is None or not creds.credentials:
        raise HTTPException(401, "missing bearer token")
    token = creds.credentials
    if settings.supabase_url:
        verified = _verify_supabase_jwt(token)
        if not verified:
            raise HTTPException(401, "invalid or expired token")
        role = verified[1]
    else:
        user = token[4:] if token.startswith("dev-") and len(token) > 4 else None
        if user is None:
            raise HTTPException(401, "invalid token (local mode expects 'dev-<user>')")
        role = "admin" if user == "admin" else "analyst"
    if role not in ("analyst", "admin"):
        role = "analyst"                    # unknown claim value: least privilege
    return role


async def require_admin(role: str = Depends(get_current_role)) -> str:
    """Dependency for admin-only routes: grants access and names the role."""
    if role != "admin":
        raise HTTPException(403, "admin role required")
    return role
