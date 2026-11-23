"""Muninn SSTI evidence analyzer and safe, bounded probe planner.

Offline only: does not issue network requests or execute template expressions.
All observations must come from authorized testing. Python >=3.10.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
import json
import re
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit


class SSTIInputError(ValueError):
    """Invalid or excessive SSTI evidence."""


@dataclass(frozen=True)
class SSTIPolicy:
    max_observations: int = 5000
    max_response_chars: int = 200_000
    max_findings: int = 2000
    max_probes: int = 12
    require_https: bool = False

    def __post_init__(self):
        if min(self.max_observations, self.max_response_chars, self.max_findings, self.max_probes) < 1:
            raise SSTIInputError("All limits must be positive")


@dataclass(frozen=True)
class SSTIProbe:
    probe_id: str
    engine_family: str
    expression: str
    expected: str
    literal_control: str
    description: str


# Harmless arithmetic expressions only. No file, network, process or object introspection.
_SAFE_PROBES = (
    SSTIProbe("jinja-arithmetic", "jinja2/twig", "{{ 17 * 19 }}", "323", "{ { 17 * 19 } }", "Double-brace arithmetic"),
    SSTIProbe("erb-arithmetic", "erb", "<%= 17 * 19 %>", "323", "<% = 17 * 19 %>", "ERB arithmetic"),
    SSTIProbe("freemarker-arithmetic", "freemarker", "${17 * 19}", "323", "$ {17 * 19}", "FreeMarker arithmetic"),
    SSTIProbe("velocity-arithmetic", "velocity", "#set($muninnProof = 17 * 19)$muninnProof", "323", "# set($muninnProof = 17 * 19)", "Velocity assignment expression"),
)


def safe_probes(policy: SSTIPolicy | None = None) -> tuple[SSTIProbe, ...]:
    """Return inert probe definitions for explicit, authorized test harnesses."""
    p = policy or SSTIPolicy()
    return _SAFE_PROBES[:p.max_probes]


@dataclass(frozen=True)
class SSTIObservation:
    url: str
    parameter: str
    scenario: str
    variant: str  # baseline | literal_control | expression | repeat_expression
    response_text: str
    status: int = 200
    probe_id: str = ""
    request_marker: str = ""  # unique, harmless marker present in the injected input
    response_marker_present: bool = False  # trusted independent attribution
    elapsed_ms: float | None = None
    verified_evaluation: bool = False  # trusted external verification, never inferred from this flag alone
    verification_reference: str = ""
    verification_trusted: bool = False


@dataclass(frozen=True)
class SSTIFinding:
    code: str
    confidence: str
    severity: str
    url_origin: str
    parameter_hash: str
    scenario_hash: str
    evidence: tuple[str, ...]
    engine_hint: str = ""


@dataclass(frozen=True)
class SSTIReport:
    findings: tuple[SSTIFinding, ...]
    analyzed: int
    skipped_out_of_scope: int
    skipped_invalid: int

    def to_json(self) -> str:
        return json.dumps({"findings": [asdict(f) for f in self.findings], "analyzed": self.analyzed,
                           "skipped_out_of_scope": self.skipped_out_of_scope,
                           "skipped_invalid": self.skipped_invalid}, sort_keys=True, indent=2)


_ENGINE_ERRORS = (
    ("jinja2", re.compile(r"\b(?:jinja2\.exceptions|TemplateSyntaxError|UndefinedError)\b", re.I)),
    ("twig", re.compile(r"\b(?:Twig\\Error|Twig_Error_|Twig\\Environment)\b", re.I)),
    ("freemarker", re.compile(r"\b(?:freemarker\.core\.|FreeMarker template error)\b", re.I)),
    ("velocity", re.compile(r"\b(?:org\.apache\.velocity\.|VelocityException)\b", re.I)),
    ("django", re.compile(r"\b(?:django\.template\.|TemplateDoesNotExist)\b", re.I)),
    ("erb", re.compile(r"\b(?:ActionView::Template::Error|ERB::Util)\b", re.I)),
    ("thymeleaf", re.compile(r"\b(?:org\.thymeleaf\.|TemplateProcessingException)\b", re.I)),
    ("handlebars", re.compile(r"\b(?:Handlebars\.Exception|handlebars\.runtime)\b", re.I)),
)


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def _origin(url: str) -> str:
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            raise ValueError("Invalid target URL")
        port = parts.port
        host = parts.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        return f"{parts.scheme}://{host}" + (f":{port}" if port else "")
    except (ValueError, TypeError) as exc:
        raise SSTIInputError("Invalid target URL") from exc


def _isolated_expected(text: str, expected: str) -> bool:
    # Avoid treating 3230, 1323, etc. as the expected arithmetic output.
    return bool(re.search(r"(?<!\d)" + re.escape(expected) + r"(?!\d)", text))


class SSTIAuditor:
    def __init__(self, policy: SSTIPolicy | None = None):
        self.policy = policy or SSTIPolicy()

    def analyze(self, observations: Iterable[SSTIObservation], *, scope_check: Callable[[str], bool]) -> SSTIReport:
        if not callable(scope_check):
            raise SSTIInputError("A scope_check callback is mandatory")
        observations = iter(observations)
        accepted: list[SSTIObservation] = []
        out_scope = invalid = 0
        # Iterate with a sentinel to fail closed on oversized streams.
        for i, obs in enumerate(observations):
            if i >= self.policy.max_observations:
                raise SSTIInputError("Observation limit exceeded")
            if not isinstance(obs, SSTIObservation):
                invalid += 1
                continue
            try:
                origin = _origin(obs.url)
                if self.policy.require_https and not origin.startswith("https://"):
                    invalid += 1
                    continue
                if not scope_check(obs.url):
                    out_scope += 1
                    continue
                if (not obs.parameter or not obs.scenario or
                    obs.variant not in {"baseline", "literal_control", "expression", "repeat_expression"} or
                    len(obs.response_text) > self.policy.max_response_chars or
                    not 100 <= obs.status <= 599):
                    invalid += 1
                    continue
            except (SSTIInputError, TypeError, ValueError):
                invalid += 1
                continue
            accepted.append(obs)

        groups: dict[tuple[str, str, str, str], list[SSTIObservation]] = {}
        for obs in accepted:
            groups.setdefault((_origin(obs.url), obs.parameter, obs.scenario, obs.probe_id), []).append(obs)

        findings: list[SSTIFinding] = []
        seen: set[tuple[str, str, str, str, str]] = set()
        probes = {p.probe_id: p for p in _SAFE_PROBES}

        def emit(code: str, confidence: str, severity: str, key: tuple[str, str, str, str], evidence: tuple[str, ...], engine: str = ""):
            origin, parameter, scenario, probe_id = key
            dedup_key = (code, origin, parameter, scenario, probe_id)
            if dedup_key in seen or len(findings) >= self.policy.max_findings:
                return
            seen.add(dedup_key)
            findings.append(SSTIFinding(code, confidence, severity, origin, _digest(parameter), _digest(scenario), evidence, engine))

        for key in sorted(groups):
            records = groups[key]
            baseline = [o for o in records if o.variant == "baseline"]
            controls = [o for o in records if o.variant == "literal_control"]
            expressions = [o for o in records if o.variant in ("expression", "repeat_expression")]
            baseline_texts = [o.response_text for o in baseline + controls]
            # Framework errors are evidence only if absent from matched controls.
            for engine, regex in _ENGINE_ERRORS:
                if any(regex.search(o.response_text) for o in expressions) and not any(regex.search(t) for t in baseline_texts):
                    emit("template_engine_error", "low", "info", key, ("Engine-specific exception appears only in expression responses",), engine)
            probe = probes.get(key[3])
            if not probe or not expressions:
                continue
            # Prevent false positives from pages that already contain the answer,
            # reflection of the original expression, and missing controls.
            has_controls = bool(baseline) and bool(controls)
            clean_controls = has_controls and all(not _isolated_expected(t, probe.expected) for t in baseline_texts)
            evaluated = [o for o in expressions if _isolated_expected(o.response_text, probe.expected)
                         and probe.expression not in o.response_text]
            if clean_controls and evaluated:
                independent = len({o.variant for o in evaluated}) >= 2
                if independent:
                    emit("template_expression_evaluated", "high", "high", key,
                         ("Expected arithmetic result absent from baseline and literal controls",
                          "Observed in expression and repeat-expression captures"), probe.engine_family)
                else:
                    emit("possible_template_evaluation", "medium", "medium", key,
                         ("Expected arithmetic result absent from baseline and literal controls",
                          "Only one expression variant available"), probe.engine_family)
            # External verification is only reported with a reference, trusted provenance,
            # matching expression response, and clean independent controls.
            if clean_controls and evaluated and any(o.verified_evaluation and o.verification_trusted and
                                                      bool(o.verification_reference.strip()) for o in evaluated):
                emit("externally_verified_template_evaluation", "high", "high", key,
                     ("Trusted external verification reference supplied",
                      "Arithmetic result corroborated by matched controls"), probe.engine_family)

        return SSTIReport(tuple(findings), len(accepted), out_scope, invalid)


__all__ = ["SSTIInputError", "SSTIPolicy", "SSTIProbe", "SSTIObservation", "SSTIFinding",
           "SSTIReport", "SSTIAuditor", "safe_probes"]
