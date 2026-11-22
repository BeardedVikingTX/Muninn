"""Offline, bounded comparison of HTTP responses for Muninn.

This module does not send traffic or determine whether a vulnerability exists.
Raw responses may contain secrets. Never serialize raw bodies/headers to logs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher
from hashlib import sha256
from statistics import median
from typing import Sequence
import json
import math
import re

from core.http_models import HTTPResponse

MAX_BODY = 2 * 1024 * 1024
MAX_TEXT = 128 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 10000
MAX_TIMINGS = 1000
_VOLATILE_HEADERS = frozenset({'date', 'set-cookie', 'expires', 'etag', 'last-modified', 'server-timing', 'x-request-id', 'traceparent', 'content-length', 'age'})
_SELECTED_HEADERS = frozenset({'content-type', 'location', 'cache-control', 'vary', 'access-control-allow-origin', 'access-control-allow-credentials', 'www-authenticate', 'content-security-policy', 'x-frame-options'})
_SENSITIVE_HEADERS = frozenset({'location', 'www-authenticate', 'set-cookie'})


class ComparisonError(ValueError):
    """Invalid or unsafe comparison input; messages never include response content."""


@dataclass(frozen=True, slots=True)
class ResponseFeatures:
    status: int
    body_bytes: int
    body_sha256: str
    content_type: str
    kind: str
    header_names: tuple[str, ...]
    header_fingerprints: tuple[tuple[str, str], ...]
    json_paths: tuple[str, ...] = ()
    json_structure_sha256: str | None = None
    text_fingerprint: str | None = None
    text_sample: str | None = field(default=None, repr=False)

    def safe_summary(self) -> dict[str, object]:
        return {"status": self.status, "body_bytes": self.body_bytes,
                "body_sha256": self.body_sha256, "content_type": self.content_type,
                "kind": self.kind, "header_names": list(self.header_names),
                "json_path_count": len(self.json_paths),
                "json_structure_sha256": self.json_structure_sha256}


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    baseline: ResponseFeatures = field(repr=False)
    candidate: ResponseFeatures = field(repr=False)
    status_changed: bool
    body_changed: bool
    body_size_delta: int
    content_type_changed: bool
    header_names_added: tuple[str, ...]
    header_names_removed: tuple[str, ...]
    selected_headers_changed: tuple[str, ...]
    json_paths_added: tuple[str, ...]
    json_paths_removed: tuple[str, ...]
    json_structure_changed: bool | None
    text_similarity: float | None
    signals: tuple[str, ...]

    def safe_summary(self) -> dict[str, object]:
        return {"baseline_status": self.baseline.status,
                "candidate_status": self.candidate.status,
                "status_changed": self.status_changed,
                "body_changed": self.body_changed,
                "body_size_delta": self.body_size_delta,
                "content_type_changed": self.content_type_changed,
                "header_names_added": list(self.header_names_added),
                "header_names_removed": list(self.header_names_removed),
                "selected_headers_changed": list(self.selected_headers_changed),
                "json_paths_added_count": len(self.json_paths_added),
                "json_paths_removed_count": len(self.json_paths_removed),
                "json_structure_changed": self.json_structure_changed,
                "text_similarity": self.text_similarity,
                "signals": list(self.signals),
                "interpretation": "observations_only_not_vulnerability_confirmation"}


@dataclass(frozen=True, slots=True)
class TimingComparison:
    baseline_count: int
    candidate_count: int
    baseline_median_ms: float
    candidate_median_ms: float
    delta_median_ms: float
    baseline_mad_ms: float
    candidate_mad_ms: float
    noise_floor_ms: float
    exceeds_noise_floor: bool

    def safe_summary(self) -> dict[str, object]:
        return {"baseline_count": self.baseline_count,
                "candidate_count": self.candidate_count,
                "baseline_median_ms": self.baseline_median_ms,
                "candidate_median_ms": self.candidate_median_ms,
                "delta_median_ms": self.delta_median_ms,
                "noise_floor_ms": self.noise_floor_ms,
                "exceeds_noise_floor": self.exceeds_noise_floor,
                "interpretation": "timing_signal_only_not_causation"}


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out = {}
    for k, v in pairs:
        if k in out:
            raise ComparisonError('duplicate JSON object key')
        out[k] = v
    return out


def _json_shape(value: object) -> tuple[tuple[str, ...], str]:
    paths: list[str] = []
    nodes = 0
    def walk(v: object, path: str, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ComparisonError('JSON structural limits exceeded')
        paths.append(path or '/')
        if isinstance(v, dict):
            return {k: walk(v[k], path + '/' + k.replace('~', '~0').replace('/', '~1'), depth + 1) for k in sorted(v)}
        if isinstance(v, list):
            return [walk(item, path + '/' + str(i), depth + 1) for i, item in enumerate(v)]
        return type(v).__name__
    shape = walk(value, '', 0)
    digest = sha256(json.dumps(shape, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
    return tuple(sorted(paths)), digest


def _features(response: HTTPResponse) -> ResponseFeatures:
    if not isinstance(response, HTTPResponse):
        raise TypeError('expected HTTPResponse')
    body = response.body
    if len(body) > MAX_BODY:
        raise ComparisonError('response body exceeds comparison limit')
    content_type = (response.headers.get('content-type') or '').split(';', 1)[0].strip().lower()
    if len(content_type) > 128 or not re.fullmatch(r'[a-z0-9!#$&^_.+\-/]*', content_type):
        content_type = 'unknown'
    names = tuple(sorted({h.name.lower() for h in response.headers}))
    header_fp = []
    for name in sorted(_SELECTED_HEADERS):
        if name in _VOLATILE_HEADERS:
            continue
        values = response.headers.get_all(name)
        if values:
            # Fingerprint only; never return raw header values.
            header_fp.append((name, sha256('\0'.join(values).encode('utf-8', 'surrogatepass')).hexdigest()))
    kind = 'binary'
    paths: tuple[str, ...] = ()
    structure = None
    sample = None
    text_fp = None
    if content_type == 'application/json' or content_type.endswith('+json'):
        kind = 'json'
        try:
            decoded = body.decode('utf-8', errors='strict')
            data = json.loads(decoded, object_pairs_hook=_unique_pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(ComparisonError('nonstandard JSON constant')))
            paths, structure = _json_shape(data)
        except (UnicodeError, ValueError, RecursionError) as exc:
            if isinstance(exc, ComparisonError):
                raise
            kind = 'invalid_json'
    elif content_type.startswith('text/') or content_type in {'application/xml', 'application/javascript', 'application/xhtml+xml'}:
        kind = 'text'
    if kind == 'text' and len(body) <= MAX_TEXT:
        try:
            sample = body.decode('utf-8', errors='strict')
            text_fp = sha256(sample.encode('utf-8')).hexdigest()
        except UnicodeError:
            kind = 'undecodable_text'
    return ResponseFeatures(response.status_code, len(body), sha256(body).hexdigest(), content_type,
                            kind, names, tuple(header_fp), paths, structure, text_fp, sample)


class ResponseComparator:
    """Deterministic offline comparison. No network, payloads, or vulnerability claims."""

    def extract(self, response: HTTPResponse) -> ResponseFeatures:
        return _features(response)

    def compare(self, baseline: HTTPResponse, candidate: HTTPResponse) -> ComparisonResult:
        a, b = self.extract(baseline), self.extract(candidate)
        af, bf = dict(a.header_fingerprints), dict(b.header_fingerprints)
        changed_headers = tuple(sorted(k for k in af.keys() | bf.keys() if af.get(k) != bf.get(k)))
        structure_changed = (a.json_structure_sha256 != b.json_structure_sha256) if a.kind == b.kind == 'json' else None
        similarity = None
        if a.text_sample is not None and b.text_sample is not None:
            # SequenceMatcher can be quadratic on hostile text; cap to 4 KiB.
            similarity = round(SequenceMatcher(None, a.text_sample[:4096], b.text_sample[:4096], autojunk=True).ratio(), 4)
        signals = []
        if a.status != b.status: signals.append('status_changed')
        if a.body_sha256 != b.body_sha256: signals.append('body_changed')
        if a.content_type != b.content_type: signals.append('content_type_changed')
        if changed_headers: signals.append('selected_headers_changed')
        if structure_changed: signals.append('json_structure_changed')
        return ComparisonResult(a, b, a.status != b.status, a.body_sha256 != b.body_sha256,
                                b.body_bytes - a.body_bytes, a.content_type != b.content_type,
                                tuple(sorted(set(b.header_names) - set(a.header_names))),
                                tuple(sorted(set(a.header_names) - set(b.header_names))),
                                changed_headers, tuple(sorted(set(b.json_paths) - set(a.json_paths))),
                                tuple(sorted(set(a.json_paths) - set(b.json_paths))),
                                structure_changed, similarity, tuple(signals))

    def compare_timings(self, baseline_ms: Sequence[float], candidate_ms: Sequence[float],
                        *, min_samples: int = 5, noise_multiplier: float = 3.0,
                        minimum_delta_ms: float = 25.0) -> TimingComparison:
        if type(min_samples) is not int or not 3 <= min_samples <= MAX_TIMINGS:
            raise ComparisonError('invalid minimum sample count')
        if not math.isfinite(noise_multiplier) or noise_multiplier < 1 or not math.isfinite(minimum_delta_ms) or minimum_delta_ms < 0:
            raise ComparisonError('invalid timing thresholds')
        samples = []
        for seq in (baseline_ms, candidate_ms):
            if not min_samples <= len(seq) <= MAX_TIMINGS:
                raise ComparisonError('insufficient or excessive timing samples')
            if any(type(x) not in (int, float) or not math.isfinite(x) or x < 0 or x > 3600000 for x in seq):
                raise ComparisonError('invalid timing sample')
            samples.append(tuple(float(x) for x in seq))
        a, b = samples
        am, bm = median(a), median(b)
        amad, bmad = median([abs(x - am) for x in a]), median([abs(x - bm) for x in b])
        noise = max(minimum_delta_ms, noise_multiplier * 1.4826 * max(amad, bmad))
        return TimingComparison(len(a), len(b), am, bm, bm - am, amad, bmad, noise, abs(bm - am) > noise)
