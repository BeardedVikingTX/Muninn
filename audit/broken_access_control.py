"""Muninn passive broken-access-control assessment.

Analyzes *pre-collected, authorized* HTTP observations. Never sends requests.
A finding is an indicator requiring validation, not proof of exploitation.
Standard library only; Python >=3.10.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from hashlib import sha256
from collections import defaultdict
from typing import Callable, Iterable, Mapping, Optional
from urllib.parse import urlsplit
import json
import re


class AccessRole(str, Enum):
    OWNER = "owner"
    PEER = "peer"
    ADMIN = "admin"
    ANONYMOUS = "anonymous"
    INVALID = "invalid"
    EXPIRED = "expired"


class FindingKind(str, Enum):
    CROSS_PRINCIPAL_ACCESS = "cross_principal_access_indicator"
    ANONYMOUS_ACCESS = "anonymous_access_indicator"
    PRIVILEGE_BOUNDARY = "privilege_boundary_indicator"
    DENIAL_INCONSISTENCY = "denial_inconsistency"
    SENSITIVE_CACHE = "sensitive_response_cache_indicator"
    MISSING_BASELINE = "missing_owner_baseline"


@dataclass(frozen=True)
class AccessObservation:
    """One captured response, labeled using trusted test-fixture metadata.

    resource_key: opaque stable identifier for the *same exact resource* across
        observations. Do not use raw resource IDs, emails, or token values.
    principal_key: opaque identifier for the authenticated test principal.
    expected_access: whether the test fixture authorizes this principal to access
        this resource; None means unknown and prevents unauthorized-access claims.
    response_fingerprint: optional *precomputed* digest of canonicalized,
        non-sensitive resource-specific response content. Never pass raw secrets.
    """
    method: str
    url: str
    resource_key: str
    principal_key: str
    role: AccessRole | str
    expected_access: Optional[bool]
    status: int
    response_fingerprint: Optional[str] = None
    content_type: str = ""
    response_headers: Mapping[str, str] = field(default_factory=dict)
    scenario_key: str = "default"


@dataclass(frozen=True)
class AccessFinding:
    kind: FindingKind
    severity: str
    confidence: str
    endpoint: str
    resource_ref: str
    principal_ref: str
    evidence: tuple[str, ...]
    recommendation: str

    def to_dict(self) -> dict:
        result = asdict(self)
        result["kind"] = self.kind.value
        return result


@dataclass(frozen=True)
class AccessReport:
    analyzed: int
    skipped_out_of_scope: int
    skipped_invalid: int
    truncated: bool
    findings: tuple[AccessFinding, ...]

    def to_dict(self) -> dict:
        return {"analyzed": self.analyzed,
                "skipped_out_of_scope": self.skipped_out_of_scope,
                "skipped_invalid": self.skipped_invalid,
                "truncated": self.truncated,
                "findings": [f.to_dict() for f in self.findings]}

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent)


class BrokenAccessControlAuditor:
    """Deterministic, fail-closed offline authorization-boundary comparator."""

    def __init__(self, *, max_observations: int = 10000,
                 max_findings: int = 1000, max_group_size: int = 100,
                 emit_missing_baseline: bool = False):
        if min(max_observations, max_findings, max_group_size) < 1:
            raise ValueError("limits must be positive")
        self.max_observations = max_observations
        self.max_findings = max_findings
        self.max_group_size = max_group_size
        self.emit_missing_baseline = emit_missing_baseline

    @staticmethod
    def _endpoint(obs: AccessObservation) -> str:
        parsed = urlsplit(obs.url)
        # Never emit raw paths: even short segments may contain private IDs.
        path_ref = sha256(parsed.path.encode("utf-8")).hexdigest()[:16]
        return f"{parsed.scheme.lower()}://{(parsed.hostname or '').lower()}/route#{path_ref}"

    @staticmethod
    def _ref(value: str) -> str:
        return sha256(value.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _valid(obs: AccessObservation) -> bool:
        try:
            parsed = urlsplit(obs.url)
            role = AccessRole(obs.role)
            return (parsed.scheme in ("http", "https") and bool(parsed.hostname)
                    and bool(obs.method.strip()) and len(obs.method) <= 16
                    and bool(obs.resource_key) and len(obs.resource_key) <= 256
                    and bool(obs.principal_key) and len(obs.principal_key) <= 256
                    and bool(obs.scenario_key) and len(obs.scenario_key) <= 128
                    and isinstance(obs.status, int) and 100 <= obs.status <= 599
                    and (obs.expected_access is None or type(obs.expected_access) is bool)
                    and (obs.response_fingerprint is None or
                         bool(re.fullmatch(r"[0-9a-fA-F]{64}", obs.response_fingerprint)))
                    and role in AccessRole)
        except (ValueError, TypeError, AttributeError):
            return False

    @staticmethod
    def _success(status: int) -> bool:
        return 200 <= status < 300

    def analyze(self, observations: Iterable[AccessObservation], *,
                scope_check: Callable[[str], bool]) -> AccessReport:
        if not callable(scope_check):
            raise TypeError("scope_check callable is required")
        groups: dict[tuple, list[AccessObservation]] = defaultdict(list)
        analyzed = skipped_scope = skipped_invalid = 0
        truncated = False
        iterator = iter(observations)
        for _ in range(self.max_observations):
            try:
                obs = next(iterator)
            except StopIteration:
                break
            if not isinstance(obs, AccessObservation) or not self._valid(obs):
                skipped_invalid += 1
                continue
            # Scope callback receives original URL; errors fail closed.
            try:
                in_scope = scope_check(obs.url) is True
            except Exception:
                in_scope = False
            if not in_scope:
                skipped_scope += 1
                continue
            analyzed += 1
            parsed = urlsplit(obs.url)
            key = (parsed.scheme.lower(), (parsed.hostname or "").lower(),
                   parsed.port, obs.method.upper(), parsed.path,
                   obs.resource_key, obs.scenario_key)
            if len(groups[key]) < self.max_group_size:
                groups[key].append(obs)
            else:
                truncated = True
        else:
            # At limit, avoid consuming the next item of a potentially stateful stream.
            truncated = True

        findings: list[AccessFinding] = []
        for key in sorted(groups):
            items = groups[key]
            owners = [o for o in items if o.expected_access is True and self._success(o.status)]
            denied = [o for o in items if o.expected_access is False]
            if not owners:
                if self.emit_missing_baseline and denied:
                    findings.append(self._finding(FindingKind.MISSING_BASELINE,
                        "info", "low", denied[0],
                        ("No successful authorized baseline was captured",),
                        "Capture an authorized control response for the exact resource"))
                continue
            owner_fps = {o.response_fingerprint.lower() for o in owners if o.response_fingerprint}
            for obs in denied:
                if len(findings) >= self.max_findings:
                    truncated = True
                    break
                if not self._success(obs.status):
                    continue
                same_content = bool(obs.response_fingerprint and
                                    obs.response_fingerprint.lower() in owner_fps)
                role = AccessRole(obs.role)
                if role in (AccessRole.ANONYMOUS, AccessRole.INVALID, AccessRole.EXPIRED):
                    kind = FindingKind.ANONYMOUS_ACCESS
                elif role == AccessRole.PEER:
                    kind = FindingKind.CROSS_PRINCIPAL_ACCESS
                else:
                    kind = FindingKind.PRIVILEGE_BOUNDARY
                evidence = ["Fixture labels this principal unauthorized for the resource",
                            "Unauthorized scenario returned HTTP 2xx",
                            "Authorized baseline for same resource returned HTTP 2xx"]
                if same_content:
                    evidence.append("Canonical response fingerprint matches authorized baseline")
                findings.append(self._finding(kind,
                    "high" if same_content else "medium",
                    "medium" if same_content else "low", obs,
                    tuple(evidence),
                    "Validate object identity and authorization using dedicated test accounts; verify server-side enforcement"))
            if len(findings) >= self.max_findings:
                truncated = True
                break
        findings.sort(key=lambda f: (f.endpoint, f.resource_ref, f.kind.value, f.principal_ref))
        return AccessReport(analyzed, skipped_scope, skipped_invalid, truncated,
                            tuple(findings[:self.max_findings]))

    def _finding(self, kind: FindingKind, severity: str, confidence: str,
                 obs: AccessObservation, evidence: tuple[str, ...],
                 recommendation: str) -> AccessFinding:
        return AccessFinding(kind, severity, confidence, self._endpoint(obs),
                             self._ref(obs.resource_key), self._ref(obs.principal_key),
                             evidence, recommendation)


__all__ = ["AccessRole", "FindingKind", "AccessObservation", "AccessFinding",
           "AccessReport", "BrokenAccessControlAuditor"]
