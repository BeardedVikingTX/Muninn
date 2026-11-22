"""Muninn's opt-in HTTP transport boundary (Python 3.10+).

No built-in network client. A caller must supply an adapter and an independently
verified approval. This module does not establish legal authorization, enforce
DNS/IP egress, or safely handle redirects on behalf of an arbitrary adapter.
Adapters MUST disable redirects, proxies, automatic retries, and connection
reuse across untrusted authorities; production adapters must pin validated
resolved IPs and revalidate redirects (preferably reject them).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from threading import Lock
from typing import Callable, Protocol
from urllib.parse import urlsplit
import re

from core.http_models import HTTPRequest, HTTPResponse, Headers, Header
from core.scope_engine import ScopeEngine


class TransportError(RuntimeError):
    """A safe, non-sensitive transport failure."""


class TransportDenied(TransportError):
    """Request was not approved for execution."""


class TransportFailure(TransportError):
    """Adapter failed or violated the response contract."""


@dataclass(frozen=True, slots=True)
class TransportApproval:
    """Caller-supplied evidence of permission; not independently authoritative."""
    engagement_id: str
    approved_by: str
    expires_at: float
    allowed_methods: frozenset[str]
    max_requests: int
    active_permission: bool = False

    def __post_init__(self) -> None:
        if not self.engagement_id or not self.approved_by or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', self.engagement_id):
            raise ValueError('Invalid approval identity')
        if type(self.active_permission) is not bool or type(self.max_requests) is not int or not 1 <= self.max_requests <= 100000:
            raise ValueError('Invalid approval limits')
        if not isinstance(self.allowed_methods, frozenset) or not self.allowed_methods or any(m not in {'GET','HEAD','OPTIONS','POST','PUT','PATCH','DELETE'} for m in self.allowed_methods):
            raise ValueError('Invalid allowed methods')
        if not isinstance(self.expires_at, (int, float)) or not 0 < self.expires_at < float('inf'):
            raise ValueError('Invalid expiry')


@dataclass(frozen=True, slots=True)
class TransportConfig:
    timeout_seconds: float = 10.0
    max_request_bytes: int = 1024 * 1024
    max_response_bytes: int = 2 * 1024 * 1024
    allow_sensitive_headers: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.timeout_seconds, (int, float)) or not 0 < self.timeout_seconds <= 30:
            raise ValueError('Invalid timeout')
        if any(type(x) is not int or not 1 <= x <= 32 * 1024 * 1024 for x in (self.max_request_bytes, self.max_response_bytes)):
            raise ValueError('Invalid byte limits')
        if type(self.allow_sensitive_headers) is not bool:
            raise ValueError('Invalid header policy')


@dataclass(frozen=True, slots=True)
class TransportResult:
    request_id: str
    status_code: int
    response: HTTPResponse = field(repr=False)

    def safe_summary(self) -> dict[str, object]:
        return {'request_id': self.request_id, 'status_code': self.status_code,
                'response_bytes': len(self.response.body)}


class Adapter(Protocol):
    def __call__(self, url: str, request: HTTPRequest, *, timeout: float,
                 max_response_bytes: int) -> HTTPResponse: ...


_BLOCKED_HEADERS = frozenset({'authorization','proxy-authorization','cookie','set-cookie',
    'x-api-key','x-auth-token','x-csrf-token','forwarded','x-forwarded-for',
    'x-forwarded-host','x-forwarded-proto','host','connection','transfer-encoding',
    'content-length','upgrade','proxy-connection','te','trailer'})


class RequestTransport:
    """Synchronous, budgeted adapter dispatcher; zero network access by default."""

    def __init__(self, *, scope: ScopeEngine, approval: TransportApproval,
                 adapter: Adapter | None = None, config: TransportConfig | None = None,
                 clock: Callable[[], float] | None = None):
        import time
        self.scope = scope
        self.approval = approval
        self.adapter = adapter
        self.config = config or TransportConfig()
        self.clock = clock or time.time
        self._lock = Lock()
        self._attempts = 0

    @property
    def attempts(self) -> int:
        with self._lock:
            return self._attempts

    def send(self, url: str, request: HTTPRequest, *, permission_confirmed: bool = False) -> TransportResult:
        """Consume a budget unit before invoking the adapter; failures still count.

        `permission_confirmed` is a deliberate, per-call assertion by the
        controlling application; it must not be derived from scope.yaml alone.
        """
        if type(permission_confirmed) is not bool or not permission_confirmed or not self.approval.active_permission:
            raise TransportDenied('Independent active permission required')
        if not isinstance(request, HTTPRequest):
            raise TransportDenied('Invalid request model')
        if self.adapter is None:
            raise TransportDenied('No approved network adapter configured')
        if request.method not in self.approval.allowed_methods:
            raise TransportDenied('HTTP method not approved')
        try:
            parts = urlsplit(url)
            if parts.scheme not in ('http', 'https') or parts.username is not None or parts.password is not None or parts.fragment or not parts.hostname:
                raise ValueError('Invalid URL')
            if request.source_url is not None and request.source_url != url:
                raise ValueError('Request URL mismatch')
            if request.target.startswith(('http://', 'https://')):
                raise ValueError('Absolute-form request target forbidden')
            if not request.target.startswith('/') or request.target != (parts.path or '/') + ('?' + parts.query if parts.query else ''):
                raise ValueError('Request target mismatch')
            decision = self.scope.classify(url)
            # Scope engine deliberately returns UNKNOWN even for local in-scope
            # matches. Require an unambiguous inclusion rule AND caller approval.
            if decision.rule is None or decision.reason != 'Local in-scope match; permission not independently verified':
                raise ValueError('Scope not included')
        except (ValueError, TypeError, AttributeError) as exc:
            raise TransportDenied('Target is invalid, mismatched, or out of scope') from None
        if request.raw is not None:
            raise TransportDenied('Raw wire replay is disabled')
        if len(request.body) > self.config.max_request_bytes:
            raise TransportDenied('Request exceeds configured size')
        for h in request.headers:
            name = h.name.casefold()
            if name in _BLOCKED_HEADERS and not (self.config.allow_sensitive_headers and name in {'authorization','cookie','x-api-key','x-auth-token','x-csrf-token'}):
                raise TransportDenied('Request includes a blocked header')
        with self._lock:
            if self.clock() >= self.approval.expires_at:
                raise TransportDenied('Approval expired')
            if self._attempts >= self.approval.max_requests:
                raise TransportDenied('Request budget exhausted')
            self._attempts += 1
            ordinal = self._attempts
        request_id = sha256(f'{self.approval.engagement_id}:{ordinal}'.encode()).hexdigest()[:24]
        try:
            response = self.adapter(url, request, timeout=float(self.config.timeout_seconds),
                                    max_response_bytes=self.config.max_response_bytes)
        except Exception as exc:
            raise TransportFailure('Transport adapter failed') from None
        if not isinstance(response, HTTPResponse) or response.raw is not None or len(response.body) > self.config.max_response_bytes:
            raise TransportFailure('Transport adapter returned an invalid or oversized response')
        # Redirects are not followed by this layer; adapters must not follow them.
        return TransportResult(request_id=request_id, status_code=response.status_code, response=response)
