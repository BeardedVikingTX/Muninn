"""Muninn CORS auditor: offline, scope-gated browser-policy analysis.

No network activity. Findings are hypotheses, not proof of data exposure.
Python 3.10+. No third-party dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from collections import defaultdict
from hashlib import sha256
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit
import json
import re


def _headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(k).strip().lower(): str(v).strip() for k, v in headers.items()}


def _origin(value: str) -> str | None:
    """Canonical HTTP(S) origin; never silently accept userinfo/path/query."""
    if value == 'null':
        return 'null'
    try:
        p = urlsplit(value)
        if p.scheme.lower() not in ('http', 'https') or not p.hostname:
            return None
        if p.username is not None or p.password is not None or p.path not in ('', '/') or p.query or p.fragment:
            return None
        port = p.port
        host = p.hostname.lower().rstrip('.')
        if not host or any(c.isspace() for c in host):
            return None
        if ':' in host:
            host = '[' + host + ']'
        default = 443 if p.scheme.lower() == 'https' else 80
        return f'{p.scheme.lower()}://{host}' + (f':{port}' if port and port != default else '')
    except (ValueError, TypeError):
        return None


def _endpoint(url: str) -> str | None:
    try:
        p = urlsplit(url)
        if p.scheme.lower() not in ('http', 'https') or not p.hostname or p.username is not None or p.password is not None:
            return None
        return f'{_origin(p.scheme + "://" + p.netloc)}{p.path or "/"}'
    except (ValueError, TypeError):
        return None


def _fingerprint(text: str) -> str:
    return sha256(text.encode('utf-8')).hexdigest()[:20]


def _csv(value: str) -> set[str]:
    return {v.strip().lower() for v in value.split(',') if v.strip()}


@dataclass(frozen=True)
class CORSCapture:
    method: str
    url: str
    status: int
    request_headers: Mapping[str, str] = field(default_factory=dict)
    response_headers: Mapping[str, str] = field(default_factory=dict)
    # Explicitly supplied by trusted caller; never inferred from HTTP status.
    sensitive: bool = False
    authenticated: bool = False
    scenario: str = ''


@dataclass(frozen=True)
class CORSFinding:
    code: str
    severity: str
    confidence: str
    endpoint_hash: str
    explanation: str
    evidence: tuple[str, ...] = ()
    cwe: str = 'CWE-942'


@dataclass(frozen=True)
class CORSReport:
    analyzed: int
    skipped: int
    findings: tuple[CORSFinding, ...]
    truncated: bool = False

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(',', ':'))


@dataclass(frozen=True)
class CORSConfig:
    max_captures: int = 10000
    max_findings: int = 2000
    # Origins explicitly controlled by assessor, not third-party production sites.
    untrusted_origins: frozenset[str] = frozenset()
    trusted_origins: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.max_captures < 1 or self.max_findings < 1:
            raise ValueError('limits must be positive')
        for origin in self.untrusted_origins | self.trusted_origins:
            if _origin(origin) != origin or origin == 'null':
                raise ValueError('policy origins must be canonical HTTP(S) origins')


class CORSAuditor:
    """Evaluate captured CORS exchanges, with mandatory explicit scope check."""

    def __init__(self, config: CORSConfig | None = None):
        self.config = config or CORSConfig()

    def analyze(self, captures: Iterable[CORSCapture], *, scope_check: Callable[[str], bool]) -> CORSReport:
        if not callable(scope_check):
            raise TypeError('scope_check callback is mandatory')
        findings: list[CORSFinding] = []
        seen: set[tuple[str, str, str]] = set()
        grouped: dict[str, list[tuple[str, str, bool, bool, str]]] = defaultdict(list)
        analyzed = skipped = 0
        truncated = False

        def emit(code: str, severity: str, confidence: str, endpoint: str, message: str, *evidence: str) -> None:
            nonlocal truncated
            key = (code, endpoint, '|'.join(evidence))
            if key in seen:
                return
            seen.add(key)
            if len(findings) >= self.config.max_findings:
                truncated = True
                return
            findings.append(CORSFinding(code, severity, confidence, _fingerprint(endpoint), message, tuple(evidence)))

        for index, capture in enumerate(captures):
            if index >= self.config.max_captures:
                truncated = True
                break
            endpoint = _endpoint(capture.url)
            if not endpoint:
                skipped += 1
                continue
            try:
                in_scope = scope_check(capture.url)
            except Exception:
                in_scope = False
            if not in_scope:
                skipped += 1
                continue
            analyzed += 1
            req = _headers(capture.request_headers)
            res = _headers(capture.response_headers)
            request_origin = req.get('origin', '')
            allow_origin = res.get('access-control-allow-origin', '')
            allow_credentials = res.get('access-control-allow-credentials', '').lower() == 'true'
            normalized_request = _origin(request_origin) if request_origin else None
            normalized_allow = _origin(allow_origin) if allow_origin else None
            valid_allow = allow_origin == '*' or (normalized_allow is not None and normalized_allow == allow_origin)
            valid_request = normalized_request is not None and normalized_request == request_origin
            allowed_by_browser = bool(valid_request and valid_allow and (
                allow_origin == '*' or normalized_allow == normalized_request
            ))
            credentialed_read = bool(allowed_by_browser and allow_credentials and allow_origin != '*')
            is_untrusted = normalized_request in self.config.untrusted_origins if normalized_request else False
            sensitivity = capture.sensitive or capture.authenticated

            if allow_origin and not valid_allow:
                emit('INVALID_ALLOW_ORIGIN', 'info', 'high', endpoint,
                     'Access-Control-Allow-Origin is not a browser-valid single origin or wildcard.', 'invalid_acao')
            if allow_origin == '*' and allow_credentials:
                emit('WILDCARD_WITH_CREDENTIALS', 'info', 'high', endpoint,
                     'Wildcard origin cannot authorize credentialed browser response reads.', 'browser_blocks_credentialed_read')
            if normalized_allow == 'null' and allow_credentials:
                emit('NULL_ORIGIN_WITH_CREDENTIALS', 'high' if sensitivity else 'medium', 'medium', endpoint,
                     'Null origin is trusted for credentialed reads; verify sensitive response exposure.', 'acao_null', 'acac_true')
            if normalized_allow and normalized_allow.startswith('http://') and endpoint.startswith('https://') and allow_credentials:
                emit('INSECURE_ORIGIN_TRUST', 'medium', 'medium', endpoint,
                     'HTTPS endpoint trusts an HTTP origin for credentialed browser reads.', 'http_origin', 'acac_true')
            if is_untrusted and credentialed_read:
                emit('UNTRUSTED_CREDENTIALED_ORIGIN', 'high' if sensitivity else 'medium', 'high', endpoint,
                     'Assessor-designated untrusted origin can read credentialed cross-origin responses.',
                     'browser_allows_credentials', 'sensitive_context' if sensitivity else 'sensitivity_unverified')
            if is_untrusted and allowed_by_browser and not allow_credentials and capture.sensitive:
                emit('UNTRUSTED_PUBLIC_READ', 'medium', 'medium', endpoint,
                     'Assessor-designated untrusted origin can read a response labeled sensitive without credentials.',
                     'browser_allows_read', 'sensitive_context')
            if allow_origin and normalized_request and normalized_allow == normalized_request and allow_origin != '*':
                vary = _csv(res.get('vary', ''))
                if 'origin' not in vary and '*' not in vary and not ('no-store' in res.get('cache-control', '').lower()):
                    emit('MISSING_VARY_ORIGIN', 'low', 'medium', endpoint,
                         'Origin-dependent CORS response lacks Vary: Origin; review shared-cache behavior.', 'origin_specific_acao', 'vary_origin_missing')
            if capture.method.upper() == 'OPTIONS' and 'access-control-request-method' in req:
                requested_method = req['access-control-request-method'].strip().lower()
                allowed_methods = _csv(res.get('access-control-allow-methods', ''))
                if allowed_by_browser and 200 <= capture.status < 300:
                    if requested_method and requested_method not in allowed_methods and '*' not in allowed_methods:
                        emit('PREFLIGHT_METHOD_NOT_ALLOWED', 'info', 'high', endpoint,
                             'Preflight response does not authorize requested method.', 'method_not_allowed')
                    requested_headers = _csv(req.get('access-control-request-headers', ''))
                    allowed_headers = _csv(res.get('access-control-allow-headers', ''))
                    if requested_headers and not requested_headers.issubset(allowed_headers) and '*' not in allowed_headers:
                        emit('PREFLIGHT_HEADERS_NOT_ALLOWED', 'info', 'high', endpoint,
                             'Preflight response does not authorize all requested headers.', 'headers_not_allowed')
            if valid_request and normalized_allow == normalized_request and allow_credentials:
                grouped[endpoint].append((normalized_request, capture.scenario, sensitivity, is_untrusted, capture.method.upper()))

        for endpoint, records in grouped.items():
            distinct = {origin for origin, _, _, _, _ in records if origin != 'null'}
            untrusted = distinct & self.config.untrusted_origins
            if len(distinct) >= 2 and untrusted:
                emit('MULTI_ORIGIN_REFLECTION', 'high' if any(r[2] for r in records) else 'medium', 'medium', endpoint,
                     'Multiple origins including assessor-controlled untrusted origin were allowed with credentials.',
                     'multiple_origins', 'assessor_untrusted_origin')
        findings.sort(key=lambda f: (f.endpoint_hash, f.code, f.evidence))
        return CORSReport(analyzed, skipped, tuple(findings), truncated)


# Backwards-friendly alias for Muninn integrations.
CorsAuditor = CORSAuditor
