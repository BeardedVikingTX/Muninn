"""Muninn XXE auditor: bounded, offline, evidence-based XML security review.

Does not parse XML with entity resolution, access files, resolve DNS, or send requests.
Observations must come from authorized testing. Never put raw XML in reports.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import ipaddress
import json
import re
from typing import Callable, Iterable, Mapping, Optional
from urllib.parse import urlsplit


@dataclass(frozen=True)
class XXEConfig:
    max_observations: int = 10000
    max_xml_bytes: int = 2_000_000
    max_response_bytes: int = 1_000_000
    max_findings: int = 5000
    max_evidence_chars: int = 160


@dataclass(frozen=True)
class XXEObservation:
    url: str
    request_xml: str = ""
    response_text: str = ""
    baseline_response_text: str = ""
    status: Optional[int] = None
    baseline_status: Optional[int] = None
    content_type: str = ""
    scenario: str = ""
    correlation_id: str = ""
    # Independently established by an authorized, isolated test harness.
    marker_verified: bool = False
    marker_provenance: str = ""
    boundary_violation_verified: bool = False
    boundary_provenance: str = ""


@dataclass(frozen=True)
class XXEOASTEvent:
    correlation_id: str
    protocol: str  # dns, http, https
    trusted: bool = False
    source_attributed: bool = False
    provenance: str = ""


@dataclass(frozen=True)
class XXEFinding:
    rule: str
    confidence: str
    severity: str
    target: str
    scenario_hash: str
    description: str
    evidence: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "rule": self.rule, "confidence": self.confidence,
            "severity": self.severity, "target": self.target,
            "scenario_hash": self.scenario_hash,
            "description": self.description, "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class XXEReport:
    observations_processed: int
    observations_skipped: int
    findings: tuple[XXEFinding, ...]

    def to_json(self) -> str:
        return json.dumps({
            "observations_processed": self.observations_processed,
            "observations_skipped": self.observations_skipped,
            "findings": [f.as_dict() for f in self.findings],
        }, sort_keys=True, separators=(",", ":"))


_DOCTYPE = re.compile(r"<!\s*DOCTYPE\b", re.I)
_EXTERNAL_DTD = re.compile(r"<!\s*DOCTYPE\b[^>]{0,2048}\b(?:SYSTEM|PUBLIC)\s+['\"]", re.I | re.S)
_EXTERNAL_ENTITY = re.compile(r"<!\s*ENTITY\s+(?:%\s+)?[\w.:-]+\s+(?:SYSTEM|PUBLIC)\s+['\"]", re.I)
_PARAMETER_ENTITY = re.compile(r"<!\s*ENTITY\s+%\s+[\w.:-]+", re.I)
_ENTITY_REFERENCE = re.compile(r"&(?:[A-Za-z_][\w.:-]*);", re.I)
_XINCLUDE = re.compile(r"<\s*(?:[A-Za-z_][\w.-]*:)?include\b[^>]{0,2048}\bhref\s*=", re.I | re.S)
_XINCLUDE_NS = re.compile(r"http://www\.w3\.org/2001/XInclude", re.I)
_SCHEMA_LOC = re.compile(r"\b(?:schemaLocation|noNamespaceSchemaLocation)\s*=", re.I)
_XML_ERROR = re.compile(
    r"(?:SAXParseException|XMLSyntaxError|ExpatError|DOCTYPE\s+is\s+disallowed|"
    r"external\s+entity\s+(?:resolution|loading|reference)|"
    r"failed\s+to\s+load\s+external\s+entity|"
    r"entity\s+['\"][^'\"]{0,80}['\"]\s+not\s+defined|"
    r"org\.xml\.sax\.|javax\.xml\.parsers\.)", re.I
)
_XML_TYPE = re.compile(r"(?:application|text)/(?:xml|[^;\s]+\+xml)\b", re.I)


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def _safe_target(url: str) -> str:
    """Only scheme/host/port/path, without userinfo, query or fragment."""
    p = urlsplit(url)
    if p.scheme.lower() not in {"http", "https"} or not p.hostname:
        raise ValueError("Only absolute HTTP(S) targets are supported")
    if p.username is not None or p.password is not None:
        raise ValueError("URL userinfo is not permitted")
    host = p.hostname.lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        host = host.encode("idna").decode("ascii")
    if ":" in host:
        host = f"[{host}]"
    port = p.port  # raises ValueError on invalid ports
    netloc = host + (f":{port}" if port is not None else "")
    # Hash path as it can contain embedded credentials, usernames or identifiers.
    return f"{p.scheme.lower()}://{netloc}/[path:{_digest(p.path or '/')}]"


def _scan_xml(xml: str) -> list[tuple[str, str, str, str]]:
    """Classify syntax only; intentionally never resolve entities or load schemas."""
    out: list[tuple[str, str, str, str]] = []
    if _DOCTYPE.search(xml):
        out.append(("doctype_present", "low", "info", "DOCTYPE declaration requires parser-policy review"))
    if _EXTERNAL_DTD.search(xml):
        out.append(("external_dtd", "low", "medium", "External DTD declaration appears in XML input"))
    if _EXTERNAL_ENTITY.search(xml):
        out.append(("external_entity", "low", "medium", "External general or parameter entity declaration appears in XML input"))
    if _PARAMETER_ENTITY.search(xml):
        out.append(("parameter_entity", "low", "info", "Parameter entity declaration appears in XML input"))
    if _XINCLUDE.search(xml) and _XINCLUDE_NS.search(xml):
        out.append(("xinclude", "low", "medium", "XInclude resource reference appears in XML input"))
    if _SCHEMA_LOC.search(xml):
        out.append(("schema_location", "low", "info", "Schema location reference requires external-loading policy review"))
    # Only flag repeated named references; do not expand or evaluate them.
    if len(_ENTITY_REFERENCE.findall(xml[:100_000])) >= 8 and _DOCTYPE.search(xml):
        out.append(("entity_expansion_pattern", "low", "medium", "Repeated entity references may warrant expansion-limit review"))
    return out


class XXEAuditor:
    def __init__(self, config: XXEConfig | None = None):
        self.config = config or XXEConfig()
        for name in ("max_observations", "max_xml_bytes", "max_response_bytes", "max_findings"):
            if getattr(self.config, name) <= 0:
                raise ValueError(f"{name} must be positive")

    def analyze(
        self,
        observations: Iterable[XXEObservation],
        *,
        scope_check: Callable[[str], bool],
        oast_events: Iterable[XXEOASTEvent] = (),
    ) -> XXEReport:
        if not callable(scope_check):
            raise TypeError("scope_check callback is required")
        events: dict[str, list[XXEOASTEvent]] = {}
        for i, event in enumerate(oast_events):
            if i >= self.config.max_observations:
                break
            if event.correlation_id and event.trusted and event.source_attributed:
                events.setdefault(event.correlation_id, []).append(event)

        findings: list[XXEFinding] = []
        seen: set[tuple[str, str, str]] = set()
        processed = skipped = 0

        for index, obs in enumerate(observations):
            if index >= self.config.max_observations:
                break
            try:
                target = _safe_target(obs.url)
                if not scope_check(obs.url):
                    skipped += 1
                    continue
            except (ValueError, UnicodeError):
                skipped += 1
                continue
            if (len(obs.request_xml.encode("utf-8", "replace")) > self.config.max_xml_bytes
                    or len(obs.response_text.encode("utf-8", "replace")) > self.config.max_response_bytes
                    or len(obs.baseline_response_text.encode("utf-8", "replace")) > self.config.max_response_bytes):
                skipped += 1
                continue
            processed += 1
            scenario = _digest(obs.scenario)
            evidence = ("xml_input_sha256=" + _digest(obs.request_xml),)

            def add(rule: str, confidence: str, severity: str, description: str, extra: tuple[str, ...] = ()) -> None:
                key = (rule, target, scenario)
                if key in seen or len(findings) >= self.config.max_findings:
                    return
                seen.add(key)
                findings.append(XXEFinding(rule, confidence, severity, target, scenario, description, evidence + extra))

            for rule, confidence, severity, description in _scan_xml(obs.request_xml):
                add(rule, confidence, severity, description)

            # XML errors can expose parser details but are not evidence of XXE.
            if _XML_ERROR.search(obs.response_text) and not _XML_ERROR.search(obs.baseline_response_text):
                add("xml_parser_error", "low", "low", "XML parser diagnostic appeared only in the candidate response")

            if obs.status is not None and obs.baseline_status is not None and obs.status != obs.baseline_status and _DOCTYPE.search(obs.request_xml):
                add("status_differential", "low", "info", "DOCTYPE-bearing request produced a different HTTP status than its baseline")

            # Correlation ID and trusted provenance must be provided by an independent harness.
            if obs.correlation_id:
                for event in events.get(obs.correlation_id, ()):
                    if not event.provenance:
                        continue
                    protocol = event.protocol.lower()
                    if protocol == "dns":
                        add("oast_dns_callback", "medium", "medium", "Attributed DNS callback indicates external resolution, not necessarily a fetched resource")
                    elif protocol in {"http", "https"}:
                        add("oast_http_callback", "high", "high", "Attributed HTTP callback is consistent with external resource retrieval")

            if obs.marker_verified and obs.marker_provenance:
                add("verified_entity_marker", "high", "high", "Independent harness verified a benign marker from external entity resolution")
            if obs.boundary_violation_verified and obs.boundary_provenance:
                add("verified_boundary_violation", "high", "critical", "Independent harness verified an unauthorized resource boundary violation")

        return XXEReport(processed, skipped, tuple(findings))


__all__ = ["XXEConfig", "XXEObservation", "XXEOASTEvent", "XXEFinding", "XXEReport", "XXEAuditor"]
