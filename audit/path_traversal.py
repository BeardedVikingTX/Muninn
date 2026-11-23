"""Muninn path traversal evidence auditor (offline, standard library only).

Never fetches URLs or reads target files. Evidence labels are supplied by a trusted
caller; suspicious syntax alone is not evidence of a successful traversal.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
from typing import Callable, Iterable, Mapping, Optional
from urllib.parse import urlsplit, unquote, parse_qsl
import json
import re

MAX_DECODE_ROUNDS = 4
_PATH_PARAM = re.compile(r"(?:file|path|filename|folder|dir|directory|template|document|download|attachment|include|resource|image|asset|name)$", re.I)
_UNIX = re.compile(r"(?:(?:^|[/\\])\.\.(?:[/\\]|$))")
_WINDOWS_DRIVE = re.compile(r"^[a-zA-Z]:[/\\]")
_UNC = re.compile(r"^(?:\\\\|//)[^/\\]+[/\\][^/\\]+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def fingerprint(value: str) -> str:
    return sha256(value.encode('utf-8', 'surrogatepass')).hexdigest()[:20]


def decode_layers(value: str, max_rounds: int = MAX_DECODE_ROUNDS) -> tuple[str, ...]:
    """Return bounded percent-decoding variants, preserving original value."""
    if not isinstance(value, str):
        raise TypeError('value must be a string')
    if max_rounds < 0 or max_rounds > 8:
        raise ValueError('max_rounds must be between 0 and 8')
    values = [value]
    for _ in range(max_rounds):
        decoded = unquote(values[-1], errors='replace')
        if decoded == values[-1]:
            break
        values.append(decoded)
    return tuple(values)


def classify_path(value: str) -> frozenset[str]:
    """Identify syntax requiring review; no filesystem access is performed."""
    variants = decode_layers(value)
    flags = set()
    if len(variants) > 1:
        flags.add('encoded_path')
    if len(variants) > 2:
        flags.add('multi_encoded_path')
    for variant in variants:
        normalized = variant.replace('\\', '/')
        if _UNIX.search(variant):
            flags.add('parent_segments')
        if _WINDOWS_DRIVE.match(variant):
            flags.add('windows_absolute_path')
        if _UNC.match(variant):
            flags.add('unc_path')
        if variant.startswith('/'):
            flags.add('absolute_path')
        if _CONTROL.search(variant):
            flags.add('control_character')
        if '\\' in variant and '..' in variant:
            flags.add('windows_separator')
        if '/./' in normalized or normalized.endswith('/.'):
            flags.add('dot_segment')
    return frozenset(flags)


def _host(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise ValueError('capture URL must be an absolute HTTP(S) URL')
    if parts.username or parts.password:
        raise ValueError('userinfo in capture URL is not supported')
    return parts.hostname.lower()


@dataclass(frozen=True)
class PathCandidate:
    location: str
    name: str
    value: str


@dataclass(frozen=True)
class TraversalCapture:
    url: str
    method: str = 'GET'
    status: int = 0
    candidates: tuple[PathCandidate, ...] = ()
    response_content_type: str = ''
    response_size: Optional[int] = None
    # Verified by independent, authorized fixtures, never inferred from status.
    verified_outside_boundary: bool = False
    verified_protected_content: bool = False
    verified_write_outside_boundary: bool = False
    fixture_id: str = ''
    baseline_status: Optional[int] = None
    scenario: str = ''


@dataclass(frozen=True)
class Finding:
    kind: str
    severity: str
    confidence: str
    url_fingerprint: str
    method: str
    candidate_location: str
    candidate_name: str
    candidate_fingerprint: str
    indicators: tuple[str, ...]
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class AuditReport:
    captures_analyzed: int
    findings: tuple[Finding, ...]
    skipped_out_of_scope: int
    truncated: bool

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(',', ':'))


@dataclass(frozen=True)
class TraversalConfig:
    max_captures: int = 10000
    max_candidates_per_capture: int = 64
    max_value_length: int = 4096
    max_findings: int = 2000
    include_unverified_indicators: bool = True

    def __post_init__(self):
        if any(getattr(self, key) < 1 for key in ('max_captures', 'max_candidates_per_capture', 'max_value_length', 'max_findings')):
            raise ValueError('limits must be positive')


class PathTraversalAuditor:
    def __init__(self, config: TraversalConfig | None = None):
        self.config = config or TraversalConfig()

    def analyze(self, captures: Iterable[TraversalCapture], *, scope_check: Callable[[str], bool]) -> AuditReport:
        if not callable(scope_check):
            raise TypeError('scope_check must be callable')
        findings: list[Finding] = []
        seen = set()
        analyzed = skipped = 0
        truncated = False
        for capture in captures:
            if analyzed + skipped >= self.config.max_captures:
                truncated = True
                break
            _host(capture.url)
            # Fail closed: scope callback exceptions propagate.
            if not scope_check(capture.url):
                skipped += 1
                continue
            analyzed += 1
            if not 0 <= capture.status <= 599:
                raise ValueError('invalid HTTP status')
            # Explicit candidates are preferred; URL parameters are extracted only
            # when the caller did not provide candidates.
            candidates = capture.candidates
            if not candidates:
                query = urlsplit(capture.url).query
                candidates = tuple(PathCandidate('query', k, v) for k, v in parse_qsl(query, keep_blank_values=True) if _PATH_PARAM.search(k))
            if len(candidates) > self.config.max_candidates_per_capture:
                truncated = True
            for candidate in candidates[:self.config.max_candidates_per_capture]:
                if len(findings) >= self.config.max_findings:
                    truncated = True
                    break
                if len(candidate.value) > self.config.max_value_length:
                    truncated = True
                    continue
                flags = classify_path(candidate.value)
                if not flags and not (capture.verified_outside_boundary or capture.verified_protected_content or capture.verified_write_outside_boundary):
                    continue
                evidence = []
                verified = bool(capture.fixture_id) and (capture.verified_outside_boundary or capture.verified_protected_content or capture.verified_write_outside_boundary)
                if capture.verified_outside_boundary and capture.fixture_id:
                    evidence.append('trusted_fixture_confirmed_boundary_escape')
                if capture.verified_protected_content and capture.fixture_id:
                    evidence.append('trusted_fixture_confirmed_protected_content')
                if capture.verified_write_outside_boundary and capture.fixture_id:
                    evidence.append('trusted_fixture_confirmed_outside_write')
                if verified:
                    confidence = 'high'
                    severity = 'critical' if capture.verified_write_outside_boundary else 'high'
                    kind = 'verified_path_boundary_violation'
                elif flags and self.config.include_unverified_indicators:
                    confidence, severity, kind = 'low', 'informational', 'suspicious_path_input'
                    if capture.status in (200, 206) and capture.baseline_status in (400, 403, 404):
                        confidence, severity = 'medium', 'low'
                        evidence.append('response_status_differs_from_rejection_baseline')
                else:
                    continue
                # Strip URL query and fragment to avoid exposing tokens/paths.
                parts = urlsplit(capture.url)
                url_key = f'{parts.scheme}://{parts.netloc}{parts.path}'
                key = (url_key, capture.method.upper(), candidate.location, candidate.name, fingerprint(candidate.value), kind)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(kind, severity, confidence, fingerprint(url_key), capture.method.upper(), candidate.location[:40], candidate.name[:80], fingerprint(candidate.value), tuple(sorted(flags)), tuple(evidence)))
            if len(findings) >= self.config.max_findings:
                truncated = True
                break
        return AuditReport(analyzed, tuple(findings), skipped, truncated)


__all__ = ['PathCandidate', 'TraversalCapture', 'TraversalConfig', 'PathTraversalAuditor', 'Finding', 'AuditReport', 'decode_layers', 'classify_path']
