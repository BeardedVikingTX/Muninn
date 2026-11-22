"""Muninn offline audit planning engine.

Turns captured transactions into bounded, privacy-conscious audit plans. NEVER
replays traffic, renders templates, contacts OAST, or interprets a scope match
as authorization. An independent execution gateway is required for active tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Iterable
from urllib.parse import urlsplit

from core.http_models import HTTPTransaction
from core.injection_points import InjectionPointDiscovery, InjectionPointError
from core.payload_loader import PayloadDefinition
from core.payload_validator import validate_catalog
from core.scope_engine import ScopeEngine

__all__ = ['AuditEngine', 'AuditEngineError', 'AuditPlan', 'PlannedTest', 'PlanSummary']

_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$')


class AuditEngineError(RuntimeError):
    """Planning failure; error messages never contain captured request content."""


@dataclass(frozen=True, slots=True)
class PlannedTest:
    id: str
    source_id: str
    point_id: str
    payload_id: str
    category: str
    decision: str  # candidate_only, blocked, manual_review
    reason_code: str
    request_budget: int  # informational upper bound; never grants requests

    def safe_summary(self) -> dict[str, object]:
        return {'id': self.id, 'point_id': self.point_id,
                'payload_id': self.payload_id, 'category': self.category,
                'decision': self.decision, 'reason_code': self.reason_code,
                'request_budget': self.request_budget}


@dataclass(frozen=True, slots=True)
class PlanSummary:
    transactions: int
    points: int
    candidates: int
    blocked: int
    manual_review: int
    scope_denied: int


@dataclass(frozen=True, slots=True)
class AuditPlan:
    run_id: str
    tests: tuple[PlannedTest, ...]
    summary: PlanSummary
    catalog_fingerprint: str

    def safe_summary(self) -> dict[str, object]:
        return {'run_id': self.run_id, 'transactions': self.summary.transactions,
                'points': self.summary.points, 'candidates': self.summary.candidates,
                'blocked': self.summary.blocked, 'manual_review': self.summary.manual_review,
                'scope_denied': self.summary.scope_denied,
                'catalog_fingerprint': self.catalog_fingerprint}


def _opaque(*values: str) -> str:
    return sha256(json.dumps(values, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()[:24]


def _target_url(tx: HTTPTransaction) -> str | None:
    """Only source_url is authoritative; do not trust Host header or inferred origin."""
    url = tx.request.source_url
    if not isinstance(url, str) or len(url) > 16384:
        return None
    try:
        parts = urlsplit(url)
        if parts.scheme not in {'http', 'https'} or not parts.netloc:
            return None
        # Ensure the captured request target and source URL refer to same path/query.
        target = urlsplit(tx.request.target)
        if target.scheme or target.netloc:
            if (target.scheme, target.netloc, target.path, target.query) != (parts.scheme, parts.netloc, parts.path, parts.query):
                return None
        elif (target.path or '/', target.query) != (parts.path or '/', parts.query):
            return None
        return url
    except ValueError:
        return None


class AuditEngine:
    """Deterministic, offline, bounded planner for existing Muninn models.

    A plan is NOT a permission token. Even 'candidate_only' means no request
    may be issued without an independent, live authorization and scope gate.
    """

    def __init__(self, *, scope: ScopeEngine, definitions: Iterable[PayloadDefinition],
                 discovery: InjectionPointDiscovery | None = None,
                 logger=None, max_transactions: int = 10000,
                 max_tests: int = 50000, max_tests_per_point: int = 32):
        if not isinstance(scope, ScopeEngine):
            raise TypeError('expected ScopeEngine')
        for name, value, cap in (('max_transactions', max_transactions, 100000),
                                 ('max_tests', max_tests, 100000),
                                 ('max_tests_per_point', max_tests_per_point, 256)):
            if type(value) is not int or not 1 <= value <= cap:
                raise ValueError('invalid ' + name)
        catalog = tuple(definitions)
        report = validate_catalog(catalog)
        if not report.valid:
            raise AuditEngineError('payload catalog semantic validation failed')
        self.scope = scope
        self.catalog = catalog
        self.discovery = discovery if discovery is not None else InjectionPointDiscovery()
        if not isinstance(self.discovery, InjectionPointDiscovery):
            raise TypeError('expected InjectionPointDiscovery')
        if logger is not None and not callable(getattr(logger, 'record', None)):
            raise TypeError('logger must support record()')
        self.logger = logger
        self.max_transactions = max_transactions
        self.max_tests = max_tests
        self.max_tests_per_point = max_tests_per_point
        # Fingerprint metadata only; never include payload template in routine summaries.
        self.catalog_fingerprint = _opaque(*[p.id for p in sorted(catalog, key=lambda p: p.id)])

    def _log(self, event: str, run_id: str, correlation_id: str, **metadata) -> None:
        if self.logger is not None:
            try:
                self.logger.record(event, run_id=run_id, component='audit_engine',
                                   correlation_id=correlation_id, metadata=metadata)
            except Exception as exc:
                raise AuditEngineError('required audit journal write failed') from exc

    def plan(self, transactions: Iterable[HTTPTransaction], *, run_id: str) -> AuditPlan:
        if type(run_id) is not str or not _ID.fullmatch(run_id):
            raise ValueError('invalid run_id')
        self._log('RUN_STARTED', run_id, run_id)
        tests: list[PlannedTest] = []
        seen: set[str] = set()
        transaction_count = point_count = denied = blocked = manual = candidates = 0
        for tx in transactions:
            transaction_count += 1
            if transaction_count > self.max_transactions:
                raise AuditEngineError('transaction planning limit exceeded')
            if not isinstance(tx, HTTPTransaction):
                raise TypeError('expected HTTPTransaction')
            if not _ID.fullmatch(tx.source_id):
                raise AuditEngineError('invalid source identifier')
            correlation = 'tx-' + _opaque(tx.source_id)
            url = _target_url(tx)
            decision = self.scope.classify(url) if url else None
            # ScopeEngine reports UNKNOWN for local inclusion, not authorization.
            scope_match = bool(decision and decision.rule is not None and
                               decision.reason == 'Local in-scope match; permission not independently verified')
            if not scope_match:
                denied += 1
                self._log('SCOPE_DENIED', run_id, correlation, reason_code='NOT_CONFIRMED')
                continue
            self._log('SCOPE_APPROVED', run_id, correlation, status='local_match_only')
            try:
                points = self.discovery.discover(tx)
            except (InjectionPointError, ValueError, TypeError) as exc:
                self._log('TEST_SKIPPED', run_id, correlation, reason_code='DISCOVERY_ERROR')
                continue
            point_count += len(points)
            self._log('INJECTION_POINT_DISCOVERED', run_id, correlation, point_count=len(points))
            for point in points:
                matching = [p for p in self.catalog if p.compatible_with(point)]
                # Never silently truncate matches: incomplete coverage is an error.
                if len(matching) > self.max_tests_per_point:
                    raise AuditEngineError('per-point planning limit exceeded')
                for definition in matching:
                    if len(tests) >= self.max_tests:
                        raise AuditEngineError('test planning limit exceeded')
                    uid = 'plan-' + _opaque(tx.source_id, point.id, definition.id)
                    if uid in seen:
                        continue
                    seen.add(uid)
                    if point.sensitive:
                        status, reason, budget = 'blocked', 'SENSITIVE_INPUT', 0
                    elif definition.destructive or definition.requires_manual_review or definition.out_of_band:
                        status, reason, budget = 'manual_review', 'MANUAL_APPROVAL_REQUIRED', 0
                    elif definition.mode == 'passive':
                        status, reason, budget = 'candidate_only', 'PASSIVE_ONLY', 0
                    else:
                        status, reason, budget = 'candidate_only', 'INDEPENDENT_AUTH_REQUIRED', 0
                    if status == 'blocked':
                        blocked += 1
                    elif status == 'manual_review':
                        manual += 1
                    else:
                        candidates += 1
                    tests.append(PlannedTest(uid, tx.source_id, point.id, definition.id,
                                             definition.category, status, reason, budget))
                    self._log('TEST_SKIPPED', run_id, correlation,
                              payload_id=definition.id, point_id=point.id,
                              reason_code=reason)
        summary = PlanSummary(transaction_count, point_count, candidates, blocked, manual, denied)
        self._log('RUN_FINISHED', run_id, run_id, status='planned', count=len(tests))
        return AuditPlan(run_id, tuple(tests), summary, self.catalog_fingerprint)
