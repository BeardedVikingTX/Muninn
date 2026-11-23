"""Muninn passive sensitive-data exposure auditor. No network activity.

Findings are indicators, not proof of unauthorized disclosure. Never store raw
secrets in serialized findings. Use trusted authorization fixtures for impact.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
from urllib.parse import urlsplit, parse_qsl
from collections import Counter
from typing import Callable, Iterable, Mapping
import json
import re

SECRET_PATTERNS = {
    'private_key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----'),
    'aws_access_key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'github_token': re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b'),
    'github_fine_grained_token': re.compile(r'\bgithub_pat_[A-Za-z0-9_]{20,}\b'),
    'slack_token': re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{12,}\b'),
    'stripe_secret': re.compile(r'\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b'),
    'jwt_like': re.compile(r'\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*\b'),
    'credential_assignment': re.compile(r'(?i)["\']?(?:password|passwd|client_secret|api[_-]?key|access[_-]?token)["\']?\s*[:=]\s*["\']([^"\'\s]{8,})["\']'),
}
SENSITIVE_QUERY_KEYS = frozenset({'password','passwd','secret','client_secret','access_token','refresh_token','id_token','api_key','apikey','authorization','session','token','code'})
SENSITIVE_HEADER_KEYS = frozenset({'authorization','proxy-authorization','set-cookie','x-api-key'})
PII_PATTERNS = {
    'email_address': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    'us_ssn_like': re.compile(r'(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)'),
}
ERROR_PATTERNS = {
    'python_traceback': re.compile(r'Traceback \(most recent call last\):'),
    'java_stack_trace': re.compile(r'(?m)^\s*at [\w.$]+\([^\n]*\.java:\d+\)'),
    'node_stack_trace': re.compile(r'(?m)^\s*at .*\([^\n]*:\d+:\d+\)'),
    'sql_error': re.compile(r'(?i)(?:SQL syntax.*MySQL|PostgreSQL.*ERROR:|SQLiteException|ORA-\d{5})'),
}
DOCUMENT_MARKERS = {
    'env_configuration': re.compile(r'(?m)^(?:DATABASE_URL|DB_PASSWORD|AWS_SECRET_ACCESS_KEY|SECRET_KEY)\s*='),
    'git_configuration': re.compile(r'(?m)^\[core\]\s*$'),
}


def fingerprint(value: str) -> str:
    return sha256(value.encode('utf-8', 'replace')).hexdigest()[:20]


def _safe_location(url: str) -> str:
    parts = urlsplit(url)
    return f'{parts.scheme}://{parts.hostname or ""}{parts.path[:180]}'


@dataclass(frozen=True)
class ExposureCapture:
    url: str
    method: str = 'GET'
    status: int = 200
    response_headers: Mapping[str, str] = field(default_factory=dict)
    response_body: str = ''
    request_headers: Mapping[str, str] = field(default_factory=dict)
    content_type: str = ''
    expected_public: bool | None = None
    unauthorized_access_verified: bool = False
    verified_sensitive_resource: bool = False
    scenario: str = ''


@dataclass(frozen=True)
class ExposureFinding:
    category: str
    confidence: str
    severity: str
    location: str
    evidence_id: str
    explanation: str


@dataclass(frozen=True)
class ExposureReport:
    findings: tuple[ExposureFinding, ...]
    examined: int
    skipped_out_of_scope: int
    truncated: bool

    def to_json(self) -> str:
        return json.dumps({'findings': [asdict(f) for f in self.findings],
                           'examined': self.examined,
                           'skipped_out_of_scope': self.skipped_out_of_scope,
                           'truncated': self.truncated}, sort_keys=True)


class SensitiveDataExposureAuditor:
    def __init__(self, *, max_captures: int = 10000, max_body_chars: int = 2_000_000,
                 max_findings: int = 5000):
        if min(max_captures, max_body_chars, max_findings) < 1:
            raise ValueError('All limits must be positive')
        self.max_captures = max_captures
        self.max_body_chars = max_body_chars
        self.max_findings = max_findings

    def analyze(self, captures: Iterable[ExposureCapture], *,
                scope_check: Callable[[str], bool]) -> ExposureReport:
        if not callable(scope_check):
            raise TypeError('A scope_check callback is required')
        findings: list[ExposureFinding] = []
        seen: set[tuple[str, str, str]] = set()
        examined = skipped = 0
        truncated = False

        def add(kind: str, confidence: str, severity: str, cap: ExposureCapture,
                explanation: str, evidence: str = '') -> None:
            nonlocal truncated
            loc = _safe_location(cap.url)
            key = (kind, loc, fingerprint(evidence or cap.url))
            if key in seen:
                return
            if len(findings) >= self.max_findings:
                truncated = True
                return
            seen.add(key)
            findings.append(ExposureFinding(kind, confidence, severity, loc,
                                            fingerprint(evidence or cap.url), explanation))

        for index, cap in enumerate(captures):
            if index >= self.max_captures:
                truncated = True
                break
            if not isinstance(cap, ExposureCapture):
                raise TypeError('All captures must be ExposureCapture instances')
            parts = urlsplit(cap.url)
            if parts.scheme not in ('http', 'https') or not parts.hostname:
                skipped += 1
                continue
            if not scope_check(cap.url):
                skipped += 1
                continue
            examined += 1
            body = cap.response_body[:self.max_body_chars]
            if len(cap.response_body) > self.max_body_chars:
                truncated = True
            headers = {str(k).lower(): str(v) for k, v in cap.response_headers.items()}
            req_headers = {str(k).lower(): str(v) for k, v in cap.request_headers.items()}
            for name, _ in parse_qsl(parts.query, keep_blank_values=True):
                if name.lower() in SENSITIVE_QUERY_KEYS:
                    add('sensitive_query_parameter', 'medium', 'medium', cap,
                        'Potential credential or authorization value appears in a URL query parameter.', name.lower())
            for key in req_headers:
                if key in SENSITIVE_HEADER_KEYS and parts.scheme == 'http':
                    add('credential_over_http', 'high', 'high', cap,
                        'Sensitive request header was sent over plaintext HTTP.', key)
            for name, pattern in SECRET_PATTERNS.items():
                for match in pattern.finditer(body):
                    value = match.group(0)
                    if name == 'credential_assignment' and re.search(r'(?i)(?:example|placeholder|changeme|your[_-]|dummy|xxxx|<)', value):
                        continue
                    add(name, 'medium', 'high' if name in {'private_key','aws_access_key','github_token','github_fine_grained_token','slack_token','stripe_secret'} else 'medium',
                        cap, 'Potential credential material appears in the response; validity and exposure policy are unverified.', name + ':' + fingerprint(value))
            for name, pattern in PII_PATTERNS.items():
                if pattern.search(body):
                    add(name, 'low', 'low', cap,
                        'Potential personal-data pattern appears in response; authorization and sensitivity require review.', name)
            for name, pattern in ERROR_PATTERNS.items():
                if pattern.search(body):
                    add(name, 'medium', 'low', cap,
                        'Verbose internal error information appears in the response.', name)
            for name, pattern in DOCUMENT_MARKERS.items():
                if pattern.search(body):
                    add(name, 'medium', 'medium', cap,
                        'Response resembles an internal configuration artifact; confirm access policy.', name)
            cache = headers.get('cache-control', '').lower()
            has_sensitive = bool(any(p.search(body) for p in SECRET_PATTERNS.values()))
            if has_sensitive and ('public' in cache or 's-maxage' in cache):
                add('sensitive_shared_cache', 'medium', 'high', cap,
                    'Potential secret-containing response permits shared caching.', cache)
            if headers.get('access-control-allow-origin') == '*' and has_sensitive:
                add('wildcard_cors_sensitive_response', 'low', 'medium', cap,
                    'Sensitive-looking response has wildcard CORS; exploitability depends on credential mode and access controls.', 'cors')
            if cap.unauthorized_access_verified and cap.verified_sensitive_resource:
                add('verified_unauthorized_disclosure', 'high', 'critical', cap,
                    'Trusted fixture indicates unauthorized access to a sensitive resource; independently validate provenance.', cap.scenario or 'verified')
        return ExposureReport(tuple(findings), examined, skipped, truncated)
