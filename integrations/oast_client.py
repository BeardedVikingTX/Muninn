"""Muninn HUGINN OAST integration: bounded, approval-gated, offline by default.

The client never performs network I/O itself. An injected adapter implements the
HTTP transport after independently enforcing DNS/IP, TLS, redirect, proxy and
response-size policies. HUGINN currently observes HTTP callbacks only (not DNS).

Do not expose raw callback records: they may contain cookies, authorization
headers, credentials, or request bodies. This module returns only sanitized
counts, timestamps and opaque correlation identifiers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from typing import Callable, Mapping, Protocol, Any
from urllib.parse import urlencode, urlsplit

__all__ = ["OASTClient", "OASTConfig", "OASTApproval", "OASTToken", "OASTObservation", "OASTError", "OASTDenied", "OASTProtocolError", "OASTAdapter"]

_HEX = re.compile(r"^[a-fA-F0-9]{16,128}$")
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

class OASTError(Exception):
    """Base exception; never includes captured data."""

class OASTDenied(OASTError):
    """A safety or authorization gate rejected the operation."""

class OASTProtocolError(OASTError):
    """The receiver returned an invalid or unsupported response."""

class OASTAdapter(Protocol):
    """Caller-provided network boundary. Must not follow redirects or use proxies."""
    def request(self, *, method: str, url: str, headers: Mapping[str, str],
                timeout: float, max_response_bytes: int) -> tuple[int, bytes]: ...

@dataclass(frozen=True, slots=True)
class OASTConfig:
    base_url: str = "https://oast.beardedviking.org"
    timeout_seconds: float = 5.0
    max_response_bytes: int = 64 * 1024
    max_polls: int = 25
    min_poll_interval_seconds: float = 1.0
    max_tokens: int = 100

    def __post_init__(self) -> None:
        p = urlsplit(self.base_url)
        if (p.scheme != "https" or not p.hostname or p.username or p.password
                or p.query or p.fragment or p.path not in ("", "/")
                or p.port not in (None, 443) or p.hostname != "oast.beardedviking.org"):
            raise ValueError("base_url must be the pinned HTTPS HUGINN origin")
        if not (0.1 <= self.timeout_seconds <= 30):
            raise ValueError("invalid timeout")
        if not (1024 <= self.max_response_bytes <= 1024 * 1024):
            raise ValueError("invalid response limit")
        if not (1 <= self.max_polls <= 10000 and 1 <= self.max_tokens <= 10000):
            raise ValueError("invalid operation limits")
        if not (0 <= self.min_poll_interval_seconds <= 3600):
            raise ValueError("invalid poll interval")

@dataclass(frozen=True, slots=True)
class OASTApproval:
    engagement_id: str
    approved_by: str
    expires_at: float
    active_permission: bool = False
    oast_permission: bool = False
    receiver_data_access_permission: bool = False

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.engagement_id) or not _ID.fullmatch(self.approved_by):
            raise ValueError("invalid approval identifier")
        if not isinstance(self.expires_at, (int, float)) or not (0 < self.expires_at < 1e20):
            raise ValueError("invalid approval expiry")

@dataclass(frozen=True, slots=True)
class OASTToken:
    """Opaque receiver token; intentionally hidden from repr and safe summaries."""
    value: str = field(repr=False)
    correlation_id: str
    created_at: float
    def safe_summary(self) -> dict[str, object]:
        return {"correlation_id": self.correlation_id, "created_at": self.created_at}

@dataclass(frozen=True, slots=True)
class OASTObservation:
    correlation_id: str
    observed: bool
    event_count: int
    checked_at: float
    source: str = "huginn_http"
    def safe_summary(self) -> dict[str, object]:
        return {"correlation_id": self.correlation_id, "observed": self.observed,
                "event_count": self.event_count, "checked_at": self.checked_at,
                "source": self.source}

def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise OASTProtocolError("receiver returned invalid JSON") from None

def _count_events(data: Any) -> int:
    """Recognize only explicit callback counts/collections; fail on unknown schemas."""
    if not isinstance(data, dict):
        raise OASTProtocolError("unexpected receiver response shape")
    for key in ("events", "callbacks", "hits", "requests"):
        value = data.get(key)
        if isinstance(value, list):
            return len(value)
    for key in ("count", "event_count", "callback_count", "hit_count"):
        value = data.get(key)
        if type(value) is int and 0 <= value <= 1_000_000:
            return value
    # A boolean explicitly named observed is usable, but not a generic status.
    if type(data.get("observed")) is bool:
        return 1 if data["observed"] else 0
    raise OASTProtocolError("unrecognized callback response schema")

class OASTClient:
    """Approval-gated HUGINN token registration and callback polling.

    The adapter is intentionally injectable: no built-in HTTP client, no DNS
    lookups, no background polling, and no callback generation occur here.
    Tokens are kept in memory only. Never persist tokens in audit logs.
    """
    def __init__(self, *, config: OASTConfig | None = None,
                 approval: OASTApproval | None = None,
                 adapter: OASTAdapter | None = None,
                 api_key: str | None = None,
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self.config = config or OASTConfig()
        self.approval = approval
        self._adapter = adapter
        self._api_key = api_key
        self._clock = clock
        self._monotonic = monotonic
        self._lock = threading.RLock()
        self._tokens: dict[str, OASTToken] = {}
        self._poll_counts: dict[str, int] = {}
        self._last_poll: dict[str, float] = {}

    def _authorize(self, *, read: bool = False) -> None:
        a = self.approval
        if (a is None or not a.active_permission or not a.oast_permission
                or (read and not a.receiver_data_access_permission)
                or self._clock() >= a.expires_at):
            raise OASTDenied("explicit current OAST approval is required")
        if self._adapter is None:
            raise OASTDenied("network adapter is not configured")
        if not isinstance(self._api_key, str) or len(self._api_key) < 16:
            raise OASTDenied("receiver authentication is required")

    def _fetch(self, path: str) -> Any:
        # No user-controlled URL or arbitrary host is accepted.
        url = self.config.base_url.rstrip("/") + path
        try:
            status, raw = self._adapter.request(  # type: ignore[union-attr]
                method="GET", url=url,
                headers={"Authorization": "Bearer " + self._api_key, "Accept": "application/json"},
                timeout=self.config.timeout_seconds,
                max_response_bytes=self.config.max_response_bytes,
            )
        except Exception:
            raise OASTError("receiver transport failed") from None
        if type(status) is not int or status != 200:
            raise OASTProtocolError("receiver returned non-success status")
        if not isinstance(raw, bytes) or len(raw) > self.config.max_response_bytes:
            raise OASTProtocolError("receiver response exceeds configured limits")
        return _json(raw)

    def register(self, *, correlation_id: str | None = None) -> OASTToken:
        """Request a fresh callback token. Requires authenticated HUGINN API."""
        with self._lock:
            self._authorize()
            if len(self._tokens) >= self.config.max_tokens:
                raise OASTDenied("token budget exhausted")
            cid = correlation_id or "oast-" + secrets.token_hex(12)
            if not _ID.fullmatch(cid) or cid in self._tokens:
                raise OASTDenied("invalid or duplicate correlation identifier")
            data = self._fetch("/?mode=new")
            if not isinstance(data, dict):
                raise OASTProtocolError("unexpected token response shape")
            token = data.get("token")
            if not isinstance(token, str) or not _HEX.fullmatch(token):
                raise OASTProtocolError("receiver did not return a valid token")
            if any(hmac.compare_digest(t.value, token) for t in self._tokens.values()):
                raise OASTProtocolError("receiver returned a duplicate token")
            entry = OASTToken(token, cid, self._clock())
            self._tokens[cid] = entry
            self._poll_counts[cid] = 0
            return entry

    def check(self, token: OASTToken) -> OASTObservation:
        """Read only event counts; raw callback contents never leave this method."""
        with self._lock:
            self._authorize(read=True)
            if not isinstance(token, OASTToken):
                raise OASTDenied("unregistered token")
            stored = self._tokens.get(token.correlation_id)
            if stored is None or not hmac.compare_digest(stored.value, token.value):
                raise OASTDenied("unregistered token")
            count = self._poll_counts[token.correlation_id]
            if count >= self.config.max_polls:
                raise OASTDenied("poll budget exhausted")
            now = self._monotonic()
            last = self._last_poll.get(token.correlation_id)
            if last is not None and now - last < self.config.min_poll_interval_seconds:
                raise OASTDenied("poll interval not elapsed")
            # Consume a poll before the transport attempt, even on errors.
            self._poll_counts[token.correlation_id] = count + 1
            self._last_poll[token.correlation_id] = now
            data = self._fetch("/check.php?" + urlencode({"token": stored.value}))
            events = _count_events(data)
            return OASTObservation(stored.correlation_id, events > 0, events, self._clock())

    def safe_summary(self) -> dict[str, object]:
        with self._lock:
            return {"receiver": "huginn_http", "registered_tokens": len(self._tokens),
                    "total_poll_attempts": sum(self._poll_counts.values()),
                    "network_enabled": self._adapter is not None}
