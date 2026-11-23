"""Muninn offline race-condition evidence analyzer.

Analyzes *authorized, pre-captured* concurrency experiments. Does not send requests.
A successful HTTP status is not evidence of a committed business operation.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from collections import defaultdict
from hashlib import sha256
from urllib.parse import urlsplit
from typing import Callable, Iterable
import json
import math


@dataclass(frozen=True)
class RacePolicy:
    scenario: str
    max_committed: int = 1
    require_overlap: bool = True
    min_attempts: int = 2

    def __post_init__(self):
        if not self.scenario or self.max_committed < 0 or self.min_attempts < 2:
            raise ValueError('Invalid race policy')


@dataclass(frozen=True)
class RaceObservation:
    url: str
    scenario: str
    run_id: str
    operation_id: str
    resource_id: str
    principal_id: str
    started_ms: float
    ended_ms: float
    status: int
    committed: bool | None = None
    commit_verified: bool = False
    idempotency_key: str | None = None


@dataclass(frozen=True)
class Finding:
    rule: str
    confidence: str
    scenario: str
    run_fingerprint: str
    resource_fingerprint: str
    evidence: dict


@dataclass(frozen=True)
class AuditReport:
    findings: tuple[Finding, ...]
    analyzed: int
    skipped: int

    def to_json(self) -> str:
        return json.dumps({'findings': [asdict(x) for x in self.findings],
                           'analyzed': self.analyzed, 'skipped': self.skipped},
                          sort_keys=True, separators=(',', ':'))


def _fingerprint(value: str) -> str:
    return sha256(value.encode('utf-8')).hexdigest()[:20]


def _valid_url(url: str) -> bool:
    try:
        p = urlsplit(url)
        return p.scheme in ('http', 'https') and bool(p.hostname) and not p.username and not p.password
    except ValueError:
        return False


def _overlap_count(items: list[RaceObservation]) -> int:
    """Maximum number of simultaneously active intervals; ends are exclusive."""
    events = []
    for x in items:
        if x.started_ms < x.ended_ms:
            events.append((x.started_ms, 1))
            events.append((x.ended_ms, -1))
    events.sort(key=lambda e: (e[0], e[1]))
    active = maximum = 0
    for _, delta in events:
        active += delta
        maximum = max(maximum, active)
    return maximum


class RaceConditionsAuditor:
    def __init__(self, *, max_observations: int = 10000,
                 max_findings: int = 2000, max_group_size: int = 2000):
        if min(max_observations, max_findings, max_group_size) < 1:
            raise ValueError('Limits must be positive')
        self.max_observations = max_observations
        self.max_findings = max_findings
        self.max_group_size = max_group_size

    def analyze(self, observations: Iterable[RaceObservation],
                policies: Iterable[RacePolicy], *,
                scope_check: Callable[[str], bool]) -> AuditReport:
        if not callable(scope_check):
            raise TypeError('scope_check callback is mandatory')
        policy_map = {}
        for policy in policies:
            if policy.scenario in policy_map:
                raise ValueError('Duplicate scenario policy')
            policy_map[policy.scenario] = policy
        groups: dict[tuple[str, str, str], list[RaceObservation]] = defaultdict(list)
        seen = set()
        analyzed = skipped = 0
        for index, item in enumerate(observations):
            if index >= self.max_observations:
                raise ValueError('Observation limit exceeded')
            if not isinstance(item, RaceObservation) or not _valid_url(item.url):
                skipped += 1
                continue
            # Fail closed: never analyze evidence outside explicit authorization.
            if not scope_check(item.url):
                skipped += 1
                continue
            if (item.scenario not in policy_map or not item.run_id or
                not item.operation_id or not item.resource_id or not item.principal_id or
                not isinstance(item.status, int) or not 100 <= item.status <= 599 or
                not all(isinstance(v, (int, float)) and math.isfinite(v)
                        for v in (item.started_ms, item.ended_ms)) or
                item.started_ms > item.ended_ms or
                (item.commit_verified and item.committed is None)):
                skipped += 1
                continue
            identity = (item.scenario, item.run_id, item.resource_id, item.operation_id)
            if identity in seen:
                skipped += 1
                continue
            seen.add(identity)
            key = (item.scenario, item.run_id, item.resource_id)
            if len(groups[key]) >= self.max_group_size:
                raise ValueError('Group size limit exceeded')
            groups[key].append(item)
            analyzed += 1
        findings = []
        for (scenario, run, resource), items in sorted(groups.items()):
            policy = policy_map[scenario]
            if len(items) < policy.min_attempts:
                continue
            overlap = _overlap_count(items)
            if policy.require_overlap and overlap < 2:
                continue
            verified = [x for x in items if x.commit_verified and x.committed is True]
            unverified_success = sum(200 <= x.status < 300 for x in items)
            duplicate_keys = len([x.idempotency_key for x in items if x.idempotency_key]) != len(
                set(x.idempotency_key for x in items if x.idempotency_key))
            base = dict(attempts=len(items), peak_concurrency=overlap,
                        verified_commits=len(verified), http_2xx=unverified_success,
                        permitted_commits=policy.max_committed)
            if len(verified) > policy.max_committed:
                rule, confidence = 'verified_commit_limit_exceeded', 'high'
            elif unverified_success > policy.max_committed:
                rule, confidence = 'multiple_success_responses', 'low'
            else:
                continue
            base['reused_idempotency_key'] = duplicate_keys
            findings.append(Finding(rule, confidence, scenario,
                                    _fingerprint(run), _fingerprint(resource), base))
            if len(findings) >= self.max_findings:
                break
        return AuditReport(tuple(findings), analyzed, skipped)
