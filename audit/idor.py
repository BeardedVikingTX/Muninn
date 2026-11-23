"""Muninn IDOR/BOLA evidence analyzer (offline; standard library only).

Inputs must be captured from authorized test identities. Expected access is
provided by a trusted fixture, never inferred from HTTP status or identifiers.
No network calls, identifier guessing, or exploitation are performed.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from hashlib import sha256
from urllib.parse import urlsplit
import json
import re
from typing import Callable, Iterable

_SUCCESS = set(range(200, 300))
_SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS'}


def _digest(value: str) -> str:
    return sha256(value.encode('utf-8')).hexdigest()[:16]


def _endpoint(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
        raise ValueError('Expected a valid HTTP(S) URL without userinfo')
    host = parts.hostname.lower()
    port = f':{parts.port}' if parts.port is not None else ''
    return f'{parts.scheme.lower()}://{host}{port}', parts.path or '/'


@dataclass(frozen=True)
class IDORCapture:
    method: str
    url: str
    resource_id: str
    principal_id: str
    expected_access: bool
    status: int
    response_fingerprint: str | None = None
    response_resource_id: str | None = None
    scenario: str = 'default'
    # This is an explicit test-fixture annotation, not inferred from response.
    confirmed_resource_disclosure: bool = False


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    confidence: str
    scenario_hash: str
    endpoint_hash: str
    resource_hash: str
    principal_hash: str
    explanation: str


@dataclass(frozen=True)
class IDORReport:
    analyzed: int
    skipped: int
    findings: tuple[Finding, ...]

    def to_json(self) -> str:
        return json.dumps({'analyzed': self.analyzed, 'skipped': self.skipped,
                           'findings': [asdict(f) for f in self.findings]},
                          sort_keys=True, separators=(',', ':'))


class IDORAuditor:
    def __init__(self, max_captures: int = 10000, max_findings: int = 2000):
        if max_captures < 1 or max_findings < 1:
            raise ValueError('Limits must be positive')
        self.max_captures = max_captures
        self.max_findings = max_findings

    def analyze(self, captures: Iterable[IDORCapture], *,
                scope_check: Callable[[str], bool]) -> IDORReport:
        if not callable(scope_check):
            raise TypeError('A scope_check callback is mandatory')
        accepted: list[tuple[IDORCapture, str]] = []
        skipped = 0
        for index, cap in enumerate(captures):
            if index >= self.max_captures:
                raise ValueError('Capture limit exceeded')
            if not isinstance(cap, IDORCapture):
                raise TypeError('Expected IDORCapture')
            origin, path = _endpoint(cap.url)
            # Never silently permit when a scope checker raises.
            if not scope_check(cap.url):
                skipped += 1
                continue
            if not cap.resource_id or not cap.principal_id or not cap.scenario:
                raise ValueError('Resource, principal and scenario are required')
            if not isinstance(cap.expected_access, bool) or not isinstance(cap.confirmed_resource_disclosure, bool):
                raise TypeError('Access annotations must be boolean')
            if not isinstance(cap.status, int) or not 100 <= cap.status <= 599:
                raise ValueError('Invalid HTTP status')
            accepted.append((cap, f'{origin}{path}'))

        # Exact same resource, endpoint, method and scenario; no inferred identity equivalence.
        groups: dict[tuple[str, str, str, str], list[IDORCapture]] = {}
        for cap, endpoint in accepted:
            key = (cap.scenario, cap.method.upper(), endpoint, cap.resource_id)
            groups.setdefault(key, []).append(cap)

        findings: list[Finding] = []
        seen: set[tuple[str, str, str, str, str]] = set()
        for (scenario, method, endpoint, resource), group in sorted(groups.items()):
            authorized = [c for c in group if c.expected_access and c.status in _SUCCESS]
            unauthorized = [c for c in group if not c.expected_access and c.status in _SUCCESS]
            for cap in unauthorized:
                # Without an authorized baseline, a 2xx alone is too ambiguous.
                if not authorized:
                    continue
                matching = any(
                    cap.response_fingerprint is not None
                    and base.response_fingerprint is not None
                    and cap.response_fingerprint == base.response_fingerprint
                    for base in authorized
                )
                # Resource-ID annotations are only meaningful when trusted test fixture supplies them.
                resource_confirmed = (cap.confirmed_resource_disclosure and
                                      cap.response_resource_id == resource)
                if resource_confirmed:
                    rule, severity, confidence = 'UNAUTHORIZED_RESOURCE_DISCLOSURE', 'high', 'high'
                    explanation = 'Trusted fixture confirms a denied principal received the target resource.'
                elif matching:
                    rule, severity, confidence = 'MATCHING_UNAUTHORIZED_RESPONSE', 'medium', 'medium'
                    explanation = 'Denied principal received a success response matching an authorized baseline fingerprint.'
                else:
                    rule, severity, confidence = 'UNEXPECTED_AUTHORIZATION_SUCCESS', 'low', 'low'
                    explanation = 'Denied principal received a successful HTTP status; content and authorization require validation.'
                if method not in _SAFE_METHODS and not resource_confirmed:
                    explanation += ' Mutation success alone does not prove an unauthorized state change.'
                dedup = (rule, scenario, method, endpoint, resource + '\x00' + cap.principal_id)
                if dedup in seen:
                    continue
                seen.add(dedup)
                findings.append(Finding(rule, severity, confidence, _digest(scenario),
                                        _digest(method + ' ' + endpoint), _digest(resource),
                                        _digest(cap.principal_id), explanation))
                if len(findings) >= self.max_findings:
                    return IDORReport(len(accepted), skipped, tuple(findings))
        return IDORReport(len(accepted), skipped, tuple(findings))
