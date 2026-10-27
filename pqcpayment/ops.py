"""Service plumbing: settings, API keys and roles, request limits, security headers,
JSON logs with request IDs, Prometheus metrics and health checks.

Settings come from PQCPAYMENT_* environment variables and are checked once at startup.
With PQCPAYMENT_ENV=production the service refuses to start without hashed API keys, a
database URL and every key listed in SECRETS. No secret has a built-in default: in
development a missing key is generated per process, so data sealed with it does not
survive a restart.

    python -m pqcpayment.ops keygen      # a new API key with its hash, and fresh secrets
"""
from __future__ import annotations

import base64
import contextvars
import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Histogram, generate_latest
from starlette.datastructures import MutableHeaders

# --- what differs between services -------------------------------------------------
PREFIX = "PQCPAYMENT"
DEFAULT_PORT = 8020
MAX_BODY_BYTES = 8_000  # the largest request is a PAN, a merchant ID and a terminal ID
# Every caller's key carries one role; each route asks for one permission. A `merchant` key's
# user name is its merchant ID, and it may only tokenize and detokenize for that merchant.
ROLES: dict[str, set[str]] = {
    "merchant": {"tokenize", "detokenize"},
    "payments_ops": {"tokenize", "detokenize", "any_merchant"},
    "key_custodian": {"rotate", "status", "kem"},
    "auditor": {"status"},
    "monitor": {"metrics"},
    "admin": {"tokenize", "detokenize", "any_merchant", "rotate", "status", "kem", "bench", "metrics"},
}
# Secrets the service needs: base64 of at least 32 random bytes each. NAME_PREVIOUS may
# list older values (comma-separated) that are still accepted for reading while rotating.
SECRETS = {
    "MASTER_KEY": "AES-256-GCM key that seals every epoch's KEM, FF1 and DUKPT keys in the database (exactly 32 bytes)",
    "AUDIT_KEY": "HMAC key for the audit chain",
}
EXACT_LENGTH = {"MASTER_KEY": 32, "MASTER_KEY_PREVIOUS": 32}
# ------------------------------------------------------------------------------------

log = logging.getLogger(PREFIX.lower())
request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")


class ConfigError(RuntimeError):
    """A setting that must stop the service from starting."""


@dataclass(frozen=True)
class Settings:
    env: str = "development"
    host: str = "127.0.0.1"
    port: int = DEFAULT_PORT
    api_keys: dict[str, dict[str, str]] = field(default_factory=dict)  # sha256 hex -> {"user", "role"}
    database_url: str = "sqlite://"  # in memory; production must name a real database
    rate_limit: int = 120  # requests per minute per client
    max_body_bytes: int = MAX_BODY_BYTES
    cors_origins: tuple[str, ...] = ()
    secret: dict[str, bytes] = field(default_factory=dict)
    previous: dict[str, tuple[bytes, ...]] = field(default_factory=dict)
    ephemeral: tuple[str, ...] = ()  # secrets generated for this process only
    log_level: str = "INFO"

    @property
    def production(self) -> bool:
        return self.env == "production"

    @property
    def demo(self) -> bool:
        """No API keys: every route is open. Only allowed in development on loopback."""
        return not self.api_keys


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _keys(raw: str, production: bool) -> dict[str, dict[str, str]]:
    """{"sha256:<hex>": {"user", "role"}} (how keys should be stored), or, in development
    only, {"<plain key>": {...}}. Plain keys are hashed straight away."""
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ConfigError(f"{PREFIX}_API_KEYS is not valid JSON") from e
    if not isinstance(entries, dict):
        raise ConfigError(f"{PREFIX}_API_KEYS must map keys to {{user, role}}")
    out = {}
    for key, ident in entries.items():
        if not isinstance(ident, dict) or not ident.get("user") or ident.get("role") not in ROLES:
            raise ConfigError(f"every API key needs a user and one of the roles {sorted(ROLES)}")
        if re.fullmatch(r"sha256:[0-9a-f]{64}", key):
            digest = key[7:]
        elif production:
            raise ConfigError(f"in production API keys must be stored as sha256:<hex> (python -m {PREFIX.lower()}.ops keygen)")
        else:
            digest = hashlib.sha256(key.encode()).hexdigest()
        out[digest] = {"user": str(ident["user"]), "role": ident["role"]}
    return out


def _secret(name: str, raw: str) -> bytes:
    try:
        val = base64.b64decode(raw, validate=True)
    except ValueError as e:
        raise ConfigError(f"{PREFIX}_{name} must be base64") from e
    want = EXACT_LENGTH.get(name)
    if (want and len(val) != want) or len(val) < 32:
        raise ConfigError(f"{PREFIX}_{name} must decode to {want or 'at least 32'} bytes")
    return val


def load_settings(env: dict[str, str] | None = None) -> Settings:
    e = os.environ if env is None else env

    def get(name: str, default: str = "") -> str:
        return e.get(f"{PREFIX}_{name}", default).strip()

    mode = get("ENV", "development")
    if mode not in ("development", "production"):
        raise ConfigError(f"{PREFIX}_ENV must be development or production, not {mode!r}")
    prod = mode == "production"

    raw = get("API_KEYS")
    if get("KEYS_FILE"):
        try:
            raw = Path(get("KEYS_FILE")).read_text(encoding="utf-8")
        except OSError as err:
            raise ConfigError(f"cannot read {PREFIX}_KEYS_FILE: {err.strerror}") from err
    keys = _keys(raw, prod) if raw else {}

    found, previous, ephemeral = {}, {}, []
    for name in SECRETS:
        if get(name):
            found[name] = _secret(name, get(name))
        elif prod:
            raise ConfigError(f"production needs {PREFIX}_{name}: {SECRETS[name]}")
        else:
            found[name] = secrets.token_bytes(EXACT_LENGTH.get(name, 32))
            ephemeral.append(name)
        previous[name] = tuple(_secret(f"{name}_PREVIOUS", v.strip()) for v in get(f"{name}_PREVIOUS").split(",") if v.strip())

    try:
        port, rate, cap = int(get("PORT", str(DEFAULT_PORT))), int(get("RATE_LIMIT", "120")), int(get("MAX_BODY_BYTES", str(MAX_BODY_BYTES)))
    except ValueError as err:
        raise ConfigError(f"{PREFIX}_PORT, _RATE_LIMIT and _MAX_BODY_BYTES must be integers") from err
    if not (0 < port < 65536 and rate > 0 and cap > 0):
        raise ConfigError(f"{PREFIX}_PORT, _RATE_LIMIT and _MAX_BODY_BYTES must be positive")

    url = get("DATABASE_URL")
    if prod and not url:
        raise ConfigError(f"production needs {PREFIX}_DATABASE_URL (sqlite:////data/{PREFIX.lower()}.db or postgresql://...)")
    url = url or Settings.database_url
    if not url.startswith(("sqlite://", "postgresql://", "postgresql+psycopg://")):
        raise ConfigError(f"{PREFIX}_DATABASE_URL must be a sqlite:// or postgresql:// URL")

    origins = tuple(o.strip() for o in get("CORS_ORIGINS").split(",") if o.strip())
    if "*" in origins:
        raise ConfigError(f"{PREFIX}_CORS_ORIGINS must list origins, not *")

    host = get("HOST", "127.0.0.1")
    if prod and not keys:
        raise ConfigError(f"production needs API keys ({PREFIX}_API_KEYS or {PREFIX}_KEYS_FILE)")
    if not keys and not _loopback(host):
        raise ConfigError(f"refusing to listen on {host} without API keys; set {PREFIX}_API_KEYS or bind to 127.0.0.1")

    return Settings(env=mode, host=host, port=port, api_keys=keys, database_url=url, rate_limit=rate,
                    max_body_bytes=cap, cors_origins=origins, secret=found, previous=previous,
                    ephemeral=tuple(ephemeral), log_level=get("LOG_LEVEL", "INFO").upper())


# --- who is calling ------------------------------------------------------------------

def _presented_key(headers) -> str:
    return headers.get("x-api-key") or headers.get("authorization", "").removeprefix("Bearer ").strip()


def require(permission: str) -> Callable[[Request], dict[str, str]]:
    """FastAPI dependency: the caller's identity, or 401/403."""
    def check(request: Request) -> dict[str, str]:
        s: Settings = request.app.state.settings
        if s.demo:
            return {"user": "", "role": "demo"}
        key = _presented_key(request.headers)
        ident = s.api_keys.get(hashlib.sha256(key.encode()).hexdigest()) if key else None
        if ident is None:
            raise HTTPException(401, "missing or unknown API key")
        if permission not in ROLES[ident["role"]]:
            raise HTTPException(403, f"role {ident['role']!r} may not {permission}")
        return ident

    return check


# --- limits --------------------------------------------------------------------------

class RateLimiter:
    """Token bucket per client: `per_minute` requests, refilled continuously.
    ponytail: per process; with several replicas put a shared limiter (Redis, the ingress) in front."""

    def __init__(self, per_minute: int):
        self.rate, self.burst = per_minute / 60.0, float(per_minute)
        self.buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def wait(self, client: str) -> float:
        """0 if the request may go ahead, else seconds until it may."""
        now = time.monotonic()
        with self._lock:
            if len(self.buckets) > 50_000:  # forget clients idle long enough to be full again
                self.buckets = {k: v for k, v in self.buckets.items() if now - v[1] < self.burst / self.rate}
            tokens, last = self.buckets.get(client, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens >= 1:
                self.buckets[client] = (tokens - 1, now)
                return 0.0
            self.buckets[client] = (tokens, now)
            return (1 - tokens) / self.rate


# --- metrics ---------------------------------------------------------------------------

REGISTRY = CollectorRegistry()
REQUESTS = Counter("http_requests_total", "HTTP requests", ["method", "route", "status"], registry=REGISTRY)
LATENCY = Histogram("http_request_duration_seconds", "Request latency", ["method", "route"], registry=REGISTRY)
ERRORS = Counter("errors_total", "Unhandled errors and failed readiness checks", ["kind"], registry=REGISTRY)
DECISIONS = Counter(f"{PREFIX.lower()}_decisions_total", "Decisions taken on requests", ["decision"], registry=REGISTRY)


# --- logs ------------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    def format(self, r: logging.LogRecord) -> str:
        out = {"ts": datetime.fromtimestamp(r.created, timezone.utc).isoformat(timespec="milliseconds"),
               "level": r.levelname, "logger": r.name, "msg": r.getMessage(), "request_id": request_id.get()}
        out.update(getattr(r, "fields", {}))
        if r.exc_info:
            out["exc"] = self.formatException(r.exc_info)
        return json.dumps(out, default=str)


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).handlers[:] = []
        logging.getLogger(name).propagate = name != "uvicorn.access"  # the Guard logs each request


# --- the outermost layer ---------------------------------------------------------------

API_CSP = "default-src 'none'; frame-ancestors 'none'"
# The consoles are single files with inline script and style.
PAGE_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'")
UNLIMITED = {"/healthz", "/readyz", "/metrics"}


class Guard:
    """Request ID, body size cap, rate limit, security headers, access log, metrics, and a
    500 that says nothing about the failure beyond its request ID."""

    def __init__(self, app, settings: Settings):
        self.app, self.s = app, settings
        self.limiter = RateLimiter(settings.rate_limit)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        rid = headers.get("x-request-id", "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", rid):
            rid = uuid.uuid4().hex
        token = request_id.set(rid)
        t0, state = time.perf_counter(), {"status": 500, "started": False}

        async def send_(msg):
            if msg["type"] == "http.response.start":
                state["status"], state["started"] = msg["status"], True
                h = MutableHeaders(scope=msg)
                h["x-request-id"] = rid
                h["x-content-type-options"] = "nosniff"
                h["x-frame-options"] = "DENY"
                h["referrer-policy"] = "no-referrer"
                h["cross-origin-opener-policy"] = "same-origin"
                h["strict-transport-security"] = "max-age=31536000"
                h["content-security-policy"] = PAGE_CSP if h.get("content-type", "").startswith("text/html") else API_CSP
                h.setdefault("cache-control", "no-store")
            await send(msg)

        try:
            if scope["path"] not in UNLIMITED:
                key = _presented_key(headers)
                digest = hashlib.sha256(key.encode()).hexdigest() if key else ""
                # known keys get their own bucket; anything else is limited by address
                client = digest if digest in self.s.api_keys else (scope.get("client") or ("?",))[0]
                wait = self.limiter.wait(client)
                if wait:
                    return await _reply(send_, 429, "rate limit exceeded", {"retry-after": str(math.ceil(wait))})
            length = headers.get("content-length")
            if length is not None and (not length.isdigit() or int(length) > self.s.max_body_bytes):
                return await _reply(send_, 413, "request body too large")
            body, size, more = [], 0, True
            while more:  # also catches chunked bodies that never declared a length
                msg = await receive()
                if msg["type"] == "http.disconnect":
                    return
                body.append(msg.get("body", b""))
                size += len(body[-1])
                if size > self.s.max_body_bytes:
                    return await _reply(send_, 413, "request body too large")
                more = msg.get("more_body", False)
            replayed = False

            async def replay():
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": b"".join(body), "more_body": False}
                return await receive()

            await self.app(scope, replay, send_)
        except Exception:
            ERRORS.labels(kind="unhandled").inc()
            log.exception("unhandled error", extra={"fields": {"path": scope["path"]}})
            if not state["started"]:
                await _reply(send_, 500, "internal error", body={"detail": "internal error", "request_id": rid})
        finally:
            route = getattr(scope.get("route"), "path", "unmatched")
            took = time.perf_counter() - t0
            REQUESTS.labels(scope["method"], route, str(state["status"])).inc()
            LATENCY.labels(scope["method"], route).observe(took)
            log.log(logging.DEBUG if scope["path"] in UNLIMITED else logging.INFO, "request",
                    extra={"fields": {"method": scope["method"], "route": route, "status": state["status"],
                                      "ms": round(took * 1000, 1), "client": (scope.get("client") or ("?",))[0]}})
            request_id.reset(token)


async def _reply(send, status: int, detail: str, headers: dict | None = None, body: dict | None = None):
    data = json.dumps(body or {"detail": detail}).encode()
    raw = [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]
    raw += [(k.encode(), v.encode()) for k, v in (headers or {}).items()]
    await send({"type": "http.response.start", "status": status, "headers": raw})
    await send({"type": "http.response.body", "body": data})


def install(app: FastAPI, settings: Settings, checks: dict[str, Callable[[], object]]) -> None:
    """Wire settings, the Guard, CORS, safe validation errors, /healthz, /readyz and
    /metrics into `app`. Each readiness check passes unless it raises or returns False."""
    app.state.settings = settings
    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_credentials=False,
                           allow_methods=["GET", "POST"], allow_headers=["content-type", "x-api-key", "authorization"])
    app.add_middleware(Guard, settings=settings)

    @app.exception_handler(RequestValidationError)
    async def _invalid(request: Request, exc: RequestValidationError):
        # FastAPI's default echoes the offending input back; keep only where and why.
        return JSONResponse({"detail": [{"loc": list(e.get("loc", ())), "msg": e.get("msg", ""), "type": e.get("type", "")}
                                        for e in exc.errors()]}, status_code=422)

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz():
        results = {}
        for name, check in checks.items():
            try:
                results[name] = check() is not False
            except Exception:
                log.warning("readiness check failed", exc_info=True, extra={"fields": {"check": name}})
                results[name] = False
        ok = all(results.values())
        if not ok:
            ERRORS.labels(kind="not_ready").inc()
        return JSONResponse({"status": "ready" if ok else "not ready", "checks": results,
                             "auth": "demo (open, loopback only)" if settings.demo else "api keys"},
                            status_code=200 if ok else 503)

    @app.get("/metrics", include_in_schema=False)
    def metrics(ident: dict = Depends(require("metrics"))):
        return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)

    if settings.ephemeral:
        log.warning("secrets generated for this process only; data sealed with them is lost on restart",
                    extra={"fields": {"secrets": list(settings.ephemeral)}})


def keygen() -> None:
    key = f"{PREFIX.lower()}_{secrets.token_urlsafe(32)}"
    print("API key (give it to the client; keep only the hash below):")
    print(f"  {key}")
    print(f"Entry for {PREFIX}_API_KEYS / {PREFIX}_KEYS_FILE:")
    print(f'  "sha256:{hashlib.sha256(key.encode()).hexdigest()}": {{"user": "<name>", "role": "<{"|".join(sorted(ROLES))}>"}}')
    for name, what in SECRETS.items():
        print(f"{PREFIX}_{name}  ({what}):")
        print(f"  {base64.b64encode(secrets.token_bytes(EXACT_LENGTH.get(name, 32))).decode()}")


if __name__ == "__main__":
    if sys.argv[1:] != ["keygen"]:
        sys.exit(f"usage: python -m {PREFIX.lower()}.ops keygen")
    keygen()
