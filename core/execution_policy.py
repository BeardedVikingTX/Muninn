"""Muninn's fail-closed, in-memory active-execution policy (Python 3.10+).

An authorization record is a caller-supplied assertion, NOT legal proof of
permission. This module has no network access. Each successful authorization
consumes a budget unit BEFORE dispatch. The transport independently checks
scope and its own approval. For multiple processes use a transactional shared
quota service; this in-memory budget is process-local only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from threading import RLock
from typing import Callable
from urllib.parse import urlsplit
import math
import re
import time

from core.http_models import HTTPRequest
from core.scope_engine import ScopeEngine

__all__ = ['ExecutionPolicy', 'ExecutionApproval', 'ExecutionLimits', 'PolicyDecision',
           'PolicyDenied', 'ExecutionPermit']

_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z')
_SAFE_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS'})
_ALL_METHODS = _SAFE_METHODS | {'POST', 'PUT', 'PATCH', 'DELETE'}
_LOCAL_SCOPE = 'Local in-scope match; permission not independently verified'


class PolicyDenied(RuntimeError):
    """Denied without disclosing target, headers, or body."""


@dataclass(frozen=True, slots=True)
class ExecutionApproval:
    engagement_id: str
    approved_by: str
    expires_at: float
    allowed_methods: frozenset[str] = frozenset({'GET', 'HEAD'})
    active_permission: bool = False
    manual_approval: bool = False
    approved_categories: frozenset[str] = frozenset()
    max_requests: int = 100
    allowed_payload_ids: frozenset[str] = frozenset()
    scope_digest: str | None = None

    def __post_init__(self):
        if any(not isinstance(x, str) or not _ID.fullmatch(x) for x in (self.engagement_id, self.approved_by)):
            raise ValueError('Invalid approval identity')
        if type(self.expires_at) not in (int, float) or not math.isfinite(self.expires_at) or self.expires_at <= 0:
            raise ValueError('Invalid expiration')
        if type(self.max_requests) is not int or not 1 <= self.max_requests <= 100000:
            raise ValueError('Invalid request budget')
        if type(self.active_permission) is not bool or type(self.manual_approval) is not bool:
            raise ValueError('Invalid approval flags')
        if not isinstance(self.allowed_methods, frozenset) or not self.allowed_methods or not self.allowed_methods <= _ALL_METHODS:
            raise ValueError('Invalid approved methods')
        for values in (self.approved_categories, self.allowed_payload_ids):
            if not isinstance(values, frozenset) or len(values) > 1024 or any(not isinstance(x, str) or not _ID.fullmatch(x) for x in values):
                raise ValueError('Invalid approved identifiers')
        if self.scope_digest is not None and (not isinstance(self.scope_digest, str) or not re.fullmatch(r'[0-9a-f]{64}', self.scope_digest)):
            raise ValueError('Invalid scope digest')


@dataclass(frozen=True, slots=True)
class ExecutionLimits:
    max_requests_per_target: int = 20
    max_requests_per_category: int = 100
    min_interval_seconds: float = 0.0
    max_request_bytes: int = 1024 * 1024
    stop_after_failures: int = 3

    def __post_init__(self):
        for key, maximum in (('max_requests_per_target', 100000), ('max_requests_per_category', 100000),
                             ('max_request_bytes', 32 * 1024 * 1024), ('stop_after_failures', 1000)):
            val = getattr(self, key)
            if type(val) is not int or not 1 <= val <= maximum:
                raise ValueError('Invalid policy limit')
        if type(self.min_interval_seconds) not in (float, int) or not math.isfinite(self.min_interval_seconds) or not 0 <= self.min_interval_seconds <= 3600:
            raise ValueError('Invalid rate interval')


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason_code: str
    remaining: int

    def safe_summary(self) -> dict[str, object]:
        return {'allowed': self.allowed, 'reason_code': self.reason_code, 'remaining': self.remaining}


@dataclass(frozen=True, slots=True)
class ExecutionPermit:
    """Accounting receipt, not a transferable authorization or network credential."""
    sequence: int
    reference: str
    engagement_id: str
    issued_at: float

    def safe_summary(self) -> dict[str, object]:
        return {'sequence': self.sequence, 'reference': self.reference, 'engagement_id': self.engagement_id}


class ExecutionPolicy:
    """Thread-safe process-local approval gate; no network I/O.

    `reserve` requires a fresh explicit caller assertion on every invocation.
    The returned receipt cannot authorize transport by itself. For a live
    request, call `execute` to apply the gate immediately before transport.
    """
    def __init__(self, *, scope: ScopeEngine, approval: ExecutionApproval,
                 limits: ExecutionLimits | None = None, clock: Callable[[], float] | None = None,
                 logger=None):
        if not isinstance(scope, ScopeEngine) or not isinstance(approval, ExecutionApproval):
            raise TypeError('Invalid policy dependencies')
        if limits is not None and not isinstance(limits, ExecutionLimits):
            raise TypeError('Invalid policy limits')
        if logger is not None and not callable(getattr(logger, 'record', None)):
            raise TypeError('Invalid audit logger')
        self.scope = scope
        self.approval = approval
        self.limits = limits or ExecutionLimits()
        self.clock = clock or time.time
        self.logger = logger
        self._lock = RLock()
        self._used = 0
        self._targets: dict[str, int] = {}
        self._categories: dict[str, int] = {}
        self._last: dict[str, float] = {}
        self._failures = 0
        self._stopped = False

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    def stop(self) -> None:
        with self._lock:
            self._stopped = True

    def report_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.limits.stop_after_failures:
                self._stopped = True

    def _check(self, url: str, request: HTTPRequest, *, category: str, payload_id: str,
               permission_confirmed: bool, destructive: bool, out_of_band: bool,
               manual_review: bool, now: float) -> tuple[str, str]:
        a = self.approval
        if type(permission_confirmed) is not bool or not permission_confirmed or not a.active_permission:
            raise PolicyDenied('ACTIVE_PERMISSION_REQUIRED')
        if self._stopped:
            raise PolicyDenied('EMERGENCY_STOP')
        if not math.isfinite(now) or now >= a.expires_at:
            raise PolicyDenied('APPROVAL_EXPIRED')
        if a.scope_digest is not None and a.scope_digest != self.scope.policy_digest:
            raise PolicyDenied('SCOPE_POLICY_CHANGED')
        if not isinstance(request, HTTPRequest) or request.raw is not None:
            raise PolicyDenied('INVALID_REQUEST')
        if request.method not in a.allowed_methods:
            raise PolicyDenied('METHOD_NOT_APPROVED')
        if type(destructive) is not bool or type(out_of_band) is not bool or type(manual_review) is not bool:
            raise PolicyDenied('INVALID_RISK_FLAGS')
        if any(not isinstance(x, str) or not _ID.fullmatch(x) for x in (category, payload_id)):
            raise PolicyDenied('INVALID_TEST_IDENTITY')
        if category not in a.approved_categories:
            raise PolicyDenied('CATEGORY_NOT_APPROVED')
        if a.allowed_payload_ids and payload_id not in a.allowed_payload_ids:
            raise PolicyDenied('PAYLOAD_NOT_APPROVED')
        if (destructive or out_of_band or manual_review or request.method not in _SAFE_METHODS) and not a.manual_approval:
            raise PolicyDenied('MANUAL_APPROVAL_REQUIRED')
        if len(request.body) > self.limits.max_request_bytes:
            raise PolicyDenied('REQUEST_TOO_LARGE')
        try:
            p = urlsplit(url)
            if not isinstance(url, str) or len(url) > 16384 or p.scheme not in ('http', 'https') or not p.hostname or p.username is not None or p.password is not None or p.fragment:
                raise ValueError
            if request.source_url is not None and request.source_url != url:
                raise ValueError
            if request.target != (p.path or '/') + ('?' + p.query if p.query else ''):
                raise ValueError
            decision = self.scope.classify(url, category=category)
            if decision.rule is None or decision.reason != _LOCAL_SCOPE or decision.eligible is False:
                raise ValueError
            authority = p.netloc.lower()
            target_key = f'{p.scheme}://{authority}'
        except (ValueError, TypeError, AttributeError):
            raise PolicyDenied('TARGET_NOT_IN_SCOPE') from None
        if self._used >= a.max_requests:
            raise PolicyDenied('GLOBAL_BUDGET_EXHAUSTED')
        if self._targets.get(target_key, 0) >= self.limits.max_requests_per_target:
            raise PolicyDenied('TARGET_BUDGET_EXHAUSTED')
        if self._categories.get(category, 0) >= self.limits.max_requests_per_category:
            raise PolicyDenied('CATEGORY_BUDGET_EXHAUSTED')
        if now - self._last.get(target_key, float('-inf')) < self.limits.min_interval_seconds:
            raise PolicyDenied('RATE_LIMITED')
        return target_key, category

    def reserve(self, url: str, request: HTTPRequest, *, category: str, payload_id: str,
                permission_confirmed: bool = False, destructive: bool = False,
                out_of_band: bool = False, manual_review: bool = False) -> ExecutionPermit:
        """Consume one attempt atomically. A failed adapter does not refund it."""
        with self._lock:
            now = float(self.clock())
            target, category_key = self._check(url, request, category=category, payload_id=payload_id,
                permission_confirmed=permission_confirmed, destructive=destructive,
                out_of_band=out_of_band, manual_review=manual_review, now=now)
            seq = self._used + 1
            reference = sha256(f'{self.approval.engagement_id}:{seq}:{payload_id}'.encode()).hexdigest()[:24]
            # Audit before permitting. A logger error prevents budget consumption and dispatch.
            if self.logger is not None:
                try:
                    self.logger.record('TEST_STARTED', run_id=self.approval.engagement_id,
                        component='execution_policy', correlation_id=reference,
                        metadata={'status': 'reserved', 'payload_id': payload_id})
                except Exception:
                    raise PolicyDenied('AUDIT_LOG_UNAVAILABLE') from None
            self._used = seq
            self._targets[target] = self._targets.get(target, 0) + 1
            self._categories[category_key] = self._categories.get(category_key, 0) + 1
            self._last[target] = now
            return ExecutionPermit(seq, reference, self.approval.engagement_id, now)

    def execute(self, transport, url: str, request: HTTPRequest, *, category: str,
                payload_id: str, permission_confirmed: bool = False,
                destructive: bool = False, out_of_band: bool = False,
                manual_review: bool = False):
        """Reserve then dispatch via existing RequestTransport (which rechecks scope).

        Caller must configure transport's independent approval and safe adapter.
        Transport exceptions count as failures and trigger the circuit breaker.
        """
        from core.request_transport import RequestTransport
        if not isinstance(transport, RequestTransport):
            raise TypeError('Expected RequestTransport')
        if transport.scope is not self.scope or transport.approval.engagement_id != self.approval.engagement_id:
            raise PolicyDenied('TRANSPORT_POLICY_MISMATCH')
        if not set(self.approval.allowed_methods).issubset(transport.approval.allowed_methods):
            raise PolicyDenied('TRANSPORT_METHOD_MISMATCH')
        self.reserve(url, request, category=category, payload_id=payload_id,
                     permission_confirmed=permission_confirmed, destructive=destructive,
                     out_of_band=out_of_band, manual_review=manual_review)
        try:
            return transport.send(url, request, permission_confirmed=permission_confirmed)
        except Exception:
            self.report_failure()
            raise
