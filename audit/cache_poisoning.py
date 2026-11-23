"""Muninn passive web-cache poisoning evidence analyzer.

No network I/O. Analyze *authorized, previously captured* cache experiments.
A finding is a review signal, never a verified exploit. Python >=3.10.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit
import json
import re

_ALLOWED_PHASES = frozenset({'baseline', 'candidate', 'followup'})
_SENSITIVE_HEADERS = frozenset({'authorization', 'cookie', 'set-cookie', 'proxy-authorization'})
_CACHE_STATUS = ('cf-cache-status', 'x-cache', 'x-cache-status', 'x-proxy-cache', 'cdn-cache-status')
_TOKEN_RE = re.compile(r'^[a-zA-Z0-9_.:-]{1,100}$')


def _headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(k).strip().lower(): str(v).strip() for k, v in headers.items()}


def _digest(value: str) -> str:
    return sha256(value.encode('utf-8', errors='replace')).hexdigest()[:20]


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        raise ValueError('HTTP(S) URL with host required')
    return f'{parsed.scheme.lower()}://{parsed.netloc.lower()}'


def _cache_hit(headers: Mapping[str, str]) -> bool:
    h = _headers(headers)
    return any(re.search(r'\bHIT\b', h.get(name, ''), flags=re.I) for name in _CACHE_STATUS)


def _cacheable_hint(headers: Mapping[str, str], status: int) -> bool:
    h = _headers(headers)
    cc = h.get('cache-control', '').lower()
    if 'no-store' in cc or 'private' in cc:
        return False
    if status not in {200, 203, 204, 301, 308}:
        return False
    return bool(re.search(r'\b(public|max-age|s-maxage|immutable)\b', cc) or h.get('expires') or _cache_hit(h))


@dataclass(frozen=True)
class CacheCapture:
    """One captured response from a designated cache experiment.

    `scenario` groups a single experiment; `phase` identifies its stage.
    `marker` is a benign, caller-chosen test string, never a credential.
    The same `cache_key` denotes the *assumed* same cache key; a caller
    must derive it from known cache configuration, not simply the URL.
    """
    scenario: str
    phase: str
    method: str
    url: str
    status: int
    request_headers: Mapping[str, str] = field(default_factory=dict)
    response_headers: Mapping[str, str] = field(default_factory=dict)
    response_body: str = ''
    cache_key: str = ''
    marker: str = ''
    varied_input: str = ''

    def __post_init__(self) -> None:
        if self.phase not in _ALLOWED_PHASES:
            raise ValueError('invalid phase')
        if not self.scenario or len(self.scenario) > 200:
            raise ValueError('invalid scenario')
        if not isinstance(self.status, int) or not 100 <= self.status <= 599:
            raise ValueError('invalid HTTP status')
        if not self.method or len(self.method) > 16:
            raise ValueError('invalid HTTP method')
        _origin(self.url)
        if self.marker and (len(self.marker) > 128 or not _TOKEN_RE.fullmatch(self.marker)):
            raise ValueError('marker must be a short benign token')
        if len(self.cache_key) > 512 or len(self.varied_input) > 120:
            raise ValueError('field too long')


@dataclass(frozen=True)
class CacheFinding:
    code: str
    severity: str
    confidence: str
    scenario_hash: str
    endpoint_hash: str
    explanation: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class CacheReport:
    inspected: int
    excluded: int
    findings: tuple[CacheFinding, ...]
    truncated: bool

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(',', ':'))


class CachePoisoningAuditor:
    """Analyze captured cache experiments without making HTTP requests.

    A scope callback is mandatory and exceptions fail closed. Callers must
    separately obtain authorization for any experiments used to produce captures.
    """
    def __init__(self, *, max_captures: int = 10000, max_body_bytes: int = 65536,
                 max_findings: int = 1000) -> None:
        if min(max_captures, max_body_bytes, max_findings) < 1:
            raise ValueError('limits must be positive')
        self.max_captures = max_captures
        self.max_body_bytes = max_body_bytes
        self.max_findings = max_findings

    def analyze(self, captures: Iterable[CacheCapture], *,
                scope_check: Callable[[str], bool]) -> CacheReport:
        if not callable(scope_check):
            raise TypeError('scope_check callable required')
        groups: dict[str, list[CacheCapture]] = {}
        inspected = excluded = 0
        truncated = False
        for capture in captures:
            if inspected + excluded >= self.max_captures:
                truncated = True
                break
            if not isinstance(capture, CacheCapture):
                raise TypeError('captures must be CacheCapture instances')
            try:
                allowed = scope_check(capture.url) is True
            except Exception:
                allowed = False
            if not allowed:
                excluded += 1
                continue
            inspected += 1
            groups.setdefault(capture.scenario, []).append(capture)
        findings: list[CacheFinding] = []
        for scenario in sorted(groups):
            items = groups[scenario]
            baseline = [x for x in items if x.phase == 'baseline']
            candidates = [x for x in items if x.phase == 'candidate']
            followups = [x for x in items if x.phase == 'followup']
            if not baseline or not candidates:
                continue
            for candidate in candidates:
                base = next((b for b in baseline if b.method.upper() == candidate.method.upper()
                             and _origin(b.url) == _origin(candidate.url)
                             and b.cache_key and b.cache_key == candidate.cache_key), None)
                if base is None:
                    continue
                body = candidate.response_body[:self.max_body_bytes]
                if not candidate.marker or candidate.marker not in body:
                    continue
                if candidate.marker in base.response_body[:self.max_body_bytes]:
                    continue
                if not _cacheable_hint(candidate.response_headers, candidate.status):
                    continue
                key_id = _digest(candidate.cache_key)
                relevant = [f for f in followups if f.cache_key == candidate.cache_key
                            and f.method.upper() == candidate.method.upper()
                            and _origin(f.url) == _origin(candidate.url)]
                observed = any(candidate.marker in f.response_body[:self.max_body_bytes]
                               and _cache_hit(f.response_headers)
                               and candidate.marker not in f.marker
                               for f in relevant)
                code = 'CACHED_MARKER_PROPAGATION' if observed else 'CACHEABLE_MARKER_REFLECTION'
                explanation = ('A benign marker appeared in a subsequent cache-HIT response; '
                               'validate cache-key assumptions and independent-client reproduction.'
                               if observed else
                               'A benign marker was reflected in a potentially cacheable response; '
                               'cross-request propagation has not been observed.')
                findings.append(CacheFinding(
                    code=code,
                    severity='medium' if observed else 'info',
                    confidence='medium' if observed else 'low',
                    scenario_hash=_digest(scenario), endpoint_hash=key_id,
                    explanation=explanation,
                    evidence=('baseline_without_marker', 'candidate_with_marker',
                              'followup_cache_hit_with_marker') if observed else
                             ('baseline_without_marker', 'candidate_with_marker', 'cacheability_hint'),
                ))
                if len(findings) >= self.max_findings:
                    truncated = True
                    break
            if truncated and len(findings) >= self.max_findings:
                break
        return CacheReport(inspected, excluded, tuple(findings), truncated)
