"""Muninn SQL injection evidence analyzer (offline, standard library only).

No network traffic, SQL payload generation, credential handling, or database access.
A caller supplies controlled observations and an explicit scope decision function.
Findings describe evidence, not an automatic claim of exploitability.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from collections import defaultdict
from hashlib import sha256
from statistics import median
from typing import Callable, Iterable, Mapping, Optional, Sequence
from urllib.parse import urlsplit
import json
import math
import re


ERROR_SIGNATURES = {
    "mysql": (r"\bSQL syntax.*?MySQL\b", r"\bmysqli?_?(?:query|fetch|error)\s*\(", r"\bYou have an error in your SQL syntax\b"),
    "postgresql": (r"\b(?:PG::SyntaxError|PG::UndefinedTable)\b", r"\bPostgreSQL.*?ERROR\b", r"\bSQLSTATE\[?(?:42P01|42601|22P02)\]?\b"),
    "mssql": (r"\bUnclosed quotation mark after the character string\b", r"\bMicrosoft OLE DB Provider for SQL Server\b", r"\bSQL Server.*?Incorrect syntax near\b"),
    "oracle": (r"\bORA-\d{5}\b", r"\bOracleException\b"),
    "sqlite": (r"\bSQLite3?::(?:SQLException|query)\b", r"\bSQLite error:.*?syntax\b", r"\bnear .{1,30}: syntax error\b"),
    "generic": (r"\b(?:SQLSTATE\[[A-Z0-9]+\]|SQL syntax error|database query failed)\b",),
}
_COMPILED = {k: tuple(re.compile(p, re.I | re.S) for p in patterns) for k, patterns in ERROR_SIGNATURES.items()}


@dataclass(frozen=True)
class SQLiObservation:
    url: str
    method: str = "GET"
    parameter: str = ""
    scenario: str = "default"
    # Explicitly labeled observations from a controlled experiment.
    variant: str = "candidate"  # baseline, candidate, boolean_true, boolean_false, timing_control, timing_candidate
    status: int = 0
    response_text: str = ""
    response_fingerprint: str = ""  # stable, normalized fingerprint from a trusted comparator
    elapsed_ms: Optional[float] = None
    # Evidence independently established by a trusted, authorized test harness.
    verified_db_effect: bool = False
    verification_reference: str = ""


@dataclass(frozen=True)
class SQLiConfig:
    max_observations: int = 10_000
    max_findings: int = 2_000
    max_response_chars: int = 200_000
    min_timing_pairs: int = 5
    timing_threshold_ms: float = 800.0
    timing_ratio: float = 2.5
    max_timing_control_spread_ms: float = 400.0
    max_timing_candidate_spread_ms: float = 600.0
    max_boolean_pairs: int = 2

    def __post_init__(self):
        if min(self.max_observations, self.max_findings, self.max_response_chars, self.min_timing_pairs, self.max_boolean_pairs) <= 0:
            raise ValueError("limits must be positive")
        if self.timing_threshold_ms < 0 or self.timing_ratio <= 1 or self.max_timing_control_spread_ms < 0 or self.max_timing_candidate_spread_ms < 0:
            raise ValueError("invalid timing configuration")


@dataclass(frozen=True)
class SQLiFinding:
    kind: str
    confidence: str
    severity: str
    endpoint_hash: str
    parameter_hash: str
    scenario_hash: str
    evidence: Mapping[str, object]
    recommendation: str


@dataclass(frozen=True)
class SQLiReport:
    analyzed: int
    excluded_out_of_scope: int
    findings: tuple[SQLiFinding, ...]
    truncated: bool = False

    def to_json(self) -> str:
        return json.dumps({"analyzed": self.analyzed,
                           "excluded_out_of_scope": self.excluded_out_of_scope,
                           "truncated": self.truncated,
                           "findings": [asdict(f) for f in self.findings]}, sort_keys=True)


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8", errors="replace")).hexdigest()[:20]


def _endpoint(url: str) -> str:
    parts = urlsplit(url)
    # Do not persist query strings, credentials, or fragments.
    return f"{parts.scheme.lower()}://{(parts.hostname or '').lower()}:{parts.port or (443 if parts.scheme.lower() == 'https' else 80)}{parts.path}"


def _valid_url(url: str) -> bool:
    try:
        p = urlsplit(url)
        return p.scheme.lower() in ("http", "https") and bool(p.hostname) and p.port != 0
    except (ValueError, TypeError):
        return False


def _spread(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    ordered = sorted(values)
    return ordered[(3 * (len(ordered) - 1)) // 4] - ordered[(len(ordered) - 1) // 4]


class SQLiAuditor:
    """Offline SQLi analyzer; never submits requests or evaluates SQL."""

    def __init__(self, config: SQLiConfig | None = None):
        self.config = config or SQLiConfig()

    def analyze(self, observations: Iterable[SQLiObservation], *, scope_check: Callable[[str], bool]) -> SQLiReport:
        if not callable(scope_check):
            raise TypeError("scope_check must be callable")
        groups: dict[tuple[str, str, str, str], list[SQLiObservation]] = defaultdict(list)
        count = excluded = 0
        truncated = False
        for obs in observations:
            if count + excluded >= self.config.max_observations:
                truncated = True
                break
            if not isinstance(obs, SQLiObservation) or not _valid_url(obs.url):
                raise ValueError("invalid SQLi observation or URL")
            # Fail closed: scope callback exceptions are not swallowed.
            if not scope_check(obs.url):
                excluded += 1
                continue
            if obs.variant not in {"baseline", "candidate", "boolean_true", "boolean_false", "timing_control", "timing_candidate"}:
                raise ValueError("unknown observation variant")
            if obs.elapsed_ms is not None and (not math.isfinite(obs.elapsed_ms) or obs.elapsed_ms < 0):
                raise ValueError("elapsed_ms must be finite and nonnegative")
            if obs.verified_db_effect and not obs.verification_reference:
                raise ValueError("verified_db_effect requires verification_reference")
            count += 1
            key = (_endpoint(obs.url), obs.method.upper(), obs.parameter, obs.scenario)
            groups[key].append(obs)

        findings: list[SQLiFinding] = []
        for (endpoint, method, parameter, scenario), group in sorted(groups.items()):
            baseline = [o for o in group if o.variant == "baseline"]
            baseline_errors = self._errors(baseline)
            candidate = [o for o in group if o.variant == "candidate"]
            for engine in sorted(self._errors(candidate) - baseline_errors):
                findings.append(self._finding("sql_error_signature", "low", "medium", endpoint, parameter, scenario,
                    {"database_family": engine, "baseline_count": len(baseline), "candidate_count": len(candidate), "baseline_present": bool(baseline)},
                    "Confirm the error is injection-dependent using matched negative controls and repeatability."))

            verified = [o for o in group if o.verified_db_effect]
            if verified:
                # Do not include raw verification references: they may contain secrets.
                findings.append(self._finding("trusted_database_effect", "high", "high", endpoint, parameter, scenario,
                    {"verified_observations": len(verified), "verification_reference_hashes": sorted({_digest(o.verification_reference) for o in verified})},
                    "Independently review the authorized verification record and assess the actual database impact."))

            true = [o for o in group if o.variant == "boolean_true" and o.response_fingerprint]
            false = [o for o in group if o.variant == "boolean_false" and o.response_fingerprint]
            if len(true) >= self.config.max_boolean_pairs and len(false) >= self.config.max_boolean_pairs:
                true_fps = {o.response_fingerprint for o in true}
                false_fps = {o.response_fingerprint for o in false}
                if len(true_fps) == 1 and len(false_fps) == 1 and true_fps.isdisjoint(false_fps):
                    base_fps = {o.response_fingerprint for o in baseline if o.response_fingerprint}
                    findings.append(self._finding("boolean_response_differential", "medium", "medium", endpoint, parameter, scenario,
                        {"true_count": len(true), "false_count": len(false), "distinct_controls": True,
                         "baseline_matches_true": bool(base_fps and base_fps == true_fps)},
                        "Repeat with randomized ordering, equivalent benign controls, and a stable normalized comparator."))

            controls = [o.elapsed_ms for o in group if o.variant == "timing_control" and o.elapsed_ms is not None]
            timed = [o.elapsed_ms for o in group if o.variant == "timing_candidate" and o.elapsed_ms is not None]
            if len(controls) >= self.config.min_timing_pairs and len(timed) >= self.config.min_timing_pairs:
                base_med, candidate_med = median(controls), median(timed)
                delta = candidate_med - base_med
                if (delta >= self.config.timing_threshold_ms and
                    candidate_med / max(base_med, 1.0) >= self.config.timing_ratio and
                    _spread(controls) <= self.config.max_timing_control_spread_ms and
                    _spread(timed) <= self.config.max_timing_candidate_spread_ms):
                    findings.append(self._finding("timing_differential", "medium", "medium", endpoint, parameter, scenario,
                        {"control_count": len(controls), "candidate_count": len(timed),
                         "median_delta_ms": round(delta, 2), "control_spread_ms": round(_spread(controls), 2),
                         "candidate_spread_ms": round(_spread(timed), 2)},
                        "Verify using interleaved randomized trials and account for infrastructure latency and caching."))

        findings.sort(key=lambda f: (f.endpoint_hash, f.parameter_hash, f.scenario_hash, f.kind))
        if len(findings) > self.config.max_findings:
            findings = findings[:self.config.max_findings]
            truncated = True
        return SQLiReport(count, excluded, tuple(findings), truncated)

    def _errors(self, observations: Sequence[SQLiObservation]) -> set[str]:
        found: set[str] = set()
        for obs in observations:
            sample = obs.response_text[:self.config.max_response_chars]
            for engine, patterns in _COMPILED.items():
                if any(p.search(sample) for p in patterns):
                    found.add(engine)
        return found

    @staticmethod
    def _finding(kind: str, confidence: str, severity: str, endpoint: str, parameter: str,
                 scenario: str, evidence: Mapping[str, object], recommendation: str) -> SQLiFinding:
        return SQLiFinding(kind, confidence, severity, _digest(endpoint), _digest(parameter),
                           _digest(scenario), evidence, recommendation)


__all__ = ["SQLiObservation", "SQLiConfig", "SQLiFinding", "SQLiReport", "SQLiAuditor", "ERROR_SIGNATURES"]
