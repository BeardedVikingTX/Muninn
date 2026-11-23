"""Muninn mass-assignment auditor: offline, policy-driven evidence correlation.

No HTTP requests are issued. Use designated test accounts and trusted before/after
snapshots. Do not put secrets in field names or object identifiers.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
from json import dumps
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlsplit
import re

SENSITIVE_FIELD_RE = re.compile(
    r"(?:^|[._\[\]-])(?:is_?admin|admin|role|roles|permission|permissions|"
    r"owner|owner_?id|user_?id|account_?id|tenant_?id|verified|is_?verified|"
    r"approved|is_?approved|balance|credit|credits|price|amount|discount|"
    r"subscription|plan|status|mfa|two_?factor|password|secret|token|"
    r"api_?key)(?:$|[._\[\]-])", re.I
)


def _fingerprint(value: str) -> str:
    return sha256(value.encode('utf-8')).hexdigest()[:16]


def _endpoint(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('Invalid HTTP(S) URL')
    return f'{parsed.scheme}://{parsed.netloc}{parsed.path}'


def flatten_fields(value: Any, prefix: str = '', *, max_depth: int = 8,
                   max_fields: int = 500) -> dict[str, Any]:
    """Flatten JSON-like objects; do not stringify sensitive values."""
    result: dict[str, Any] = {}
    def visit(obj: Any, path: str, depth: int) -> None:
        if len(result) >= max_fields or depth > max_depth:
            return
        if isinstance(obj, Mapping):
            for key, child in obj.items():
                if not isinstance(key, str) or not key or len(result) >= max_fields:
                    continue
                visit(child, f'{path}.{key}' if path else key, depth + 1)
        elif isinstance(obj, (list, tuple)):
            for index, child in enumerate(obj[:max_fields]):
                if len(result) >= max_fields:
                    break
                visit(child, f'{path}[{index}]', depth + 1)
        elif path:
            result[path] = obj
    visit(value, prefix, 0)
    return result


@dataclass(frozen=True)
class AssignmentPolicy:
    """Explicit test fixture authorization policy for a single operation."""
    operation: str
    allowed_fields: frozenset[str] = frozenset()
    protected_fields: frozenset[str] = frozenset()
    allow_unknown_fields: bool = False

    def __post_init__(self) -> None:
        if not self.operation:
            raise ValueError('operation is required')
        if self.allowed_fields & self.protected_fields:
            raise ValueError('A field cannot be both allowed and protected')


@dataclass(frozen=True)
class AssignmentCapture:
    operation: str
    method: str
    url: str
    principal_id: str
    object_id: str
    request_json: Mapping[str, Any]
    status: int
    before_json: Mapping[str, Any] | None = None
    after_json: Mapping[str, Any] | None = None
    # Set only when before/after snapshots come from trusted independent reads.
    snapshots_trusted: bool = False


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    confidence: str
    operation: str
    endpoint_fingerprint: str
    object_fingerprint: str
    field: str
    explanation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class AssignmentReport:
    findings: list[Finding] = field(default_factory=list)
    captures_examined: int = 0
    captures_skipped: int = 0

    def to_json(self) -> str:
        return dumps({
            'captures_examined': self.captures_examined,
            'captures_skipped': self.captures_skipped,
            'findings': [finding.to_dict() for finding in self.findings],
        }, sort_keys=True, separators=(',', ':'))


class MassAssignmentAuditor:
    def __init__(self, *, max_captures: int = 10000,
                 max_findings: int = 2000, max_fields: int = 500) -> None:
        if min(max_captures, max_findings, max_fields) < 1:
            raise ValueError('Limits must be positive')
        self.max_captures = max_captures
        self.max_findings = max_findings
        self.max_fields = max_fields

    def analyze(self, captures: Iterable[AssignmentCapture],
                policies: Iterable[AssignmentPolicy], *,
                scope_check: Callable[[str], bool]) -> AssignmentReport:
        if not callable(scope_check):
            raise ValueError('A scope_check callback is required')
        policy_map = {policy.operation: policy for policy in policies}
        report = AssignmentReport()
        seen: set[tuple[str, str, str, str]] = set()
        for index, capture in enumerate(captures):
            if index >= self.max_captures:
                break
            try:
                endpoint = _endpoint(capture.url)
                if not scope_check(capture.url):
                    report.captures_skipped += 1
                    continue
            except (ValueError, Exception):
                report.captures_skipped += 1
                continue
            policy = policy_map.get(capture.operation)
            if policy is None:
                report.captures_skipped += 1
                continue
            report.captures_examined += 1
            requested = flatten_fields(capture.request_json, max_fields=self.max_fields)
            before = flatten_fields(capture.before_json, max_fields=self.max_fields) if capture.before_json is not None else {}
            after = flatten_fields(capture.after_json, max_fields=self.max_fields) if capture.after_json is not None else {}
            for name, value in requested.items():
                protected = name in policy.protected_fields
                unknown = name not in policy.allowed_fields and not protected and not policy.allow_unknown_fields
                heuristic = bool(SENSITIVE_FIELD_RE.search(name)) and name not in policy.allowed_fields
                if not (protected or unknown or heuristic):
                    continue
                # Only a trusted independent before/after comparison can raise confidence.
                changed = (capture.snapshots_trusted and capture.before_json is not None
                           and capture.after_json is not None and name in before and name in after
                           and before[name] != after[name] and after[name] == value)
                if changed:
                    code, confidence, severity = 'PROTECTED_FIELD_CHANGED', 'high', 'high' if protected else 'medium'
                    explanation = 'Trusted snapshots show the submitted field value persisted; verify authorization expectations.'
                elif 200 <= capture.status < 300:
                    code, confidence, severity = 'UNAUTHORIZED_FIELD_SUBMITTED', 'low', 'low'
                    explanation = 'A disallowed or sensitive-looking field was submitted with a successful HTTP status; persistence is unverified.'
                else:
                    continue
                key = (capture.operation, capture.object_id, name, code)
                if key in seen:
                    continue
                seen.add(key)
                report.findings.append(Finding(
                    code, severity, confidence, capture.operation,
                    _fingerprint(endpoint), _fingerprint(capture.object_id),
                    name, explanation,
                ))
                if len(report.findings) >= self.max_findings:
                    return report
        return report
