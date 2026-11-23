"""Muninn RCE evidence analyzer (offline, standard library only).

Analyzes authorized, previously collected observations. Never issues requests,
executes payloads, runs commands, or treats a response status as RCE proof.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
from typing import Callable, Iterable, Mapping, Optional
from urllib.parse import urlsplit
import json
import math
import re

MAX_TEXT = 128_000
SURFACES = {
    "command": (r"\b(?:child_process\.(?:exec|execSync|spawn)|subprocess\.(?:run|Popen|call)|os\.system|Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\b",),
    "evaluation": (r"\b(?:eval|exec|new\s+Function)\s*\(",),
    "deserialization": (r"\b(?:pickle\.loads|yaml\.unsafe_load|unserialize|ObjectInputStream|BinaryFormatter)\s*\(?",),
    "template": (r"\b(?:render_template_string|Template\s*\(|from_string\s*\()",),
}
ERROR_PATTERNS = {
    "shell_error": re.compile(r"(?:/bin/(?:sh|bash):|(?:cmd\.exe|powershell)(?:\s*:|\.exe\s*:)|command not found)", re.I),
    "runtime_trace": re.compile(r"(?:Traceback \(most recent call last\)|Exception in thread|at [\w.$]+\([^\n]{0,150}:\d+\)|Fatal error: Uncaught)", re.I),
    "template_error": re.compile(r"(?:TemplateSyntaxError|UndefinedError|jinja2\.exceptions|Twig\\Error)", re.I),
}
RUNTIME_HEADERS = {
    "x-powered-by": "runtime_header",
    "server": "server_header",
    "x-aspnet-version": "aspnet_version",
}


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8", errors="replace")).hexdigest()[:20]


def _origin(url: str) -> str:
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError("URL must be an absolute HTTP(S) URL without credentials")
    try:
        port = p.port
    except ValueError as exc:
        raise ValueError("Invalid URL port") from exc
    return f"{p.scheme}://{p.hostname.lower()}:{port or (443 if p.scheme == 'https' else 80)}"


def _headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(k).lower(): str(v)[:512] for k, v in headers.items()}


@dataclass(frozen=True)
class RCEObservation:
    url: str
    method: str = "GET"
    scenario: str = "default"
    status: int = 0
    response_text: str = ""
    response_headers: Mapping[str, str] = field(default_factory=dict)
    source_code: str = ""
    baseline_status: Optional[int] = None
    baseline_response_text: str = ""
    # A trusted external harness must verify the marker is produced by the
    # server-side test action, not merely reflected in a response.
    marker_verified: bool = False
    marker_expected: str = ""
    marker_observed: str = ""
    # Independent, explicitly approved test fixture evidence.
    execution_verified: bool = False
    verification_method: str = ""
    test_fixture_id: str = ""
    timing_ms: Optional[float] = None
    baseline_timing_ms: Optional[float] = None
    timing_samples: int = 0
    baseline_timing_samples: int = 0


@dataclass(frozen=True)
class RCEFinding:
    category: str
    confidence: str
    severity: str
    origin: str
    endpoint_fingerprint: str
    scenario_fingerprint: str
    evidence: tuple[str, ...]
    recommendation: str


@dataclass(frozen=True)
class RCEReport:
    analyzed: int
    skipped_out_of_scope: int
    findings: tuple[RCEFinding, ...]
    truncated: bool = False

    def to_json(self) -> str:
        return json.dumps({
            "analyzed": self.analyzed,
            "skipped_out_of_scope": self.skipped_out_of_scope,
            "truncated": self.truncated,
            "findings": [asdict(f) for f in self.findings],
        }, sort_keys=True, separators=(",", ":"))


class RCEAuditor:
    def __init__(self, *, max_observations: int = 10000,
                 max_findings: int = 2000, max_text_bytes: int = MAX_TEXT,
                 min_timing_samples: int = 5, timing_ratio: float = 3.0,
                 timing_delta_ms: float = 1000.0):
        if min(max_observations, max_findings, max_text_bytes, min_timing_samples) < 1:
            raise ValueError("Limits must be positive")
        if timing_ratio <= 1 or timing_delta_ms <= 0:
            raise ValueError("Invalid timing thresholds")
        self.max_observations = max_observations
        self.max_findings = max_findings
        self.max_text_bytes = max_text_bytes
        self.min_timing_samples = min_timing_samples
        self.timing_ratio = timing_ratio
        self.timing_delta_ms = timing_delta_ms

    def analyze(self, observations: Iterable[RCEObservation], *,
                scope_check: Callable[[str], bool]) -> RCEReport:
        if not callable(scope_check):
            raise TypeError("scope_check callback is required")
        findings: list[RCEFinding] = []
        seen: set[tuple[str, str, str]] = set()
        analyzed = skipped = 0
        truncated = False
        for index, obs in enumerate(observations):
            if index >= self.max_observations:
                truncated = True
                break
            origin = _origin(obs.url)
            if not scope_check(obs.url):
                skipped += 1
                continue
            analyzed += 1
            endpoint = _digest(obs.url)
            scenario = _digest(obs.scenario)
            response = obs.response_text[:self.max_text_bytes]
            baseline = obs.baseline_response_text[:self.max_text_bytes]
            source = obs.source_code[:self.max_text_bytes]
            headers = _headers(obs.response_headers)

            def add(category: str, confidence: str, severity: str,
                    evidence: tuple[str, ...], recommendation: str) -> None:
                nonlocal truncated
                key = (endpoint, scenario, category)
                if key in seen:
                    return
                if len(findings) >= self.max_findings:
                    truncated = True
                    return
                seen.add(key)
                findings.append(RCEFinding(category, confidence, severity,
                                           origin, endpoint, scenario,
                                           evidence, recommendation))

            if source:
                for kind, patterns in SURFACES.items():
                    if any(re.search(pattern, source, re.I) for pattern in patterns):
                        add(f"potential_{kind}_sink", "low", "informational",
                            ("Potentially dangerous API found in supplied source",),
                            "Trace untrusted inputs to this sink and inspect contextual safeguards")

            for name, pattern in ERROR_PATTERNS.items():
                if pattern.search(response) and not pattern.search(baseline):
                    add(name, "low", "informational",
                        ("Error signature appears in observed response but not baseline",),
                        "Inspect error handling and independently verify whether untrusted input reaches execution")

            if obs.baseline_status is not None and obs.status != obs.baseline_status:
                add("status_anomaly", "low", "informational",
                    ("HTTP status differs from supplied baseline",),
                    "Check whether the response difference is application logic rather than execution")

            if obs.timing_ms is not None and obs.baseline_timing_ms is not None:
                values = (obs.timing_ms, obs.baseline_timing_ms)
                if all(math.isfinite(x) and x >= 0 for x in values):
                    if (obs.timing_samples >= self.min_timing_samples and
                        obs.baseline_timing_samples >= self.min_timing_samples and
                        obs.timing_ms - obs.baseline_timing_ms >= self.timing_delta_ms and
                        obs.timing_ms >= obs.baseline_timing_ms * self.timing_ratio):
                        add("timing_anomaly", "low", "informational",
                            ("Timing difference exceeds configured thresholds across supplied samples",),
                            "Repeat randomized control/intervention trials; timing alone is not RCE proof")

            for name, label in RUNTIME_HEADERS.items():
                if name in headers:
                    add(label, "informational", "informational",
                        (f"Response includes {name} fingerprint header",),
                        "Use framework context to prioritize review, not to infer exploitability")

            if obs.marker_verified and obs.marker_expected and obs.marker_observed == obs.marker_expected:
                if obs.test_fixture_id and obs.verification_method:
                    add("verified_execution_marker", "high", "high",
                        ("Trusted harness confirmed non-reflected execution marker",
                         "Verification fixture and method were supplied"),
                        "Retain controlled fixture evidence and confirm authorization boundary")
                else:
                    add("marker_claim_incomplete", "low", "informational",
                        ("Marker match claimed without fixture and verification provenance",),
                        "Provide independent provenance and exclude simple reflection")

            if obs.execution_verified:
                if obs.test_fixture_id and obs.verification_method:
                    add("verified_execution", "high", "critical",
                        ("Trusted harness reports execution in an authorized test fixture",),
                        "Independently review fixture provenance, execution context and impact")
                else:
                    add("execution_claim_incomplete", "low", "informational",
                        ("Execution claimed without fixture and verification provenance",),
                        "Require independently reviewed execution evidence")
        return RCEReport(analyzed, skipped, tuple(findings), truncated)
