"""Muninn deterministic evidence-confidence assessment.

Offline, standard-library-only confidence evaluation for security audit findings.
Scores are prioritization heuristics, NOT calibrated probabilities, severity, or bounty estimates.

Python >= 3.10. No network access, filesystem access, or secrets logging.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from math import isfinite
from typing import Iterable, Mapping
import json


class EvidenceKind(str, Enum):
    INDICATOR = "indicator"             # e.g., reflection, error, suspicious parameter
    DIFFERENTIAL = "differential"       # matched baseline vs altered response
    REPRODUCTION = "reproduction"       # repeatable behavior with controls
    IMPACT = "impact"                   # observed unauthorized effect
    NEGATIVE_CONTROL = "negative_control"  # control supports hypothesis when it fails as expected
    CONTRADICTION = "contradiction"     # evidence inconsistent with hypothesis


class EvidenceQuality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ScopeStatus(str, Enum):
    AUTHORIZED = "authorized"
    UNKNOWN = "unknown"
    PROHIBITED = "prohibited"


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    CORROBORATED = "corroborated"
    VALIDATED = "validated"
    INCONCLUSIVE = "inconclusive"
    REFUTED = "refuted"


# Weights are deliberately modest: independent controls matter more than signatures.
WEIGHTS: Mapping[EvidenceKind, int] = {
    EvidenceKind.INDICATOR: 8,
    EvidenceKind.DIFFERENTIAL: 18,
    EvidenceKind.REPRODUCTION: 22,
    EvidenceKind.IMPACT: 28,
    EvidenceKind.NEGATIVE_CONTROL: 14,
    EvidenceKind.CONTRADICTION: -30,
}
QUALITY_MULTIPLIERS: Mapping[EvidenceQuality, float] = {
    EvidenceQuality.LOW: 0.5,
    EvidenceQuality.MEDIUM: 0.75,
    EvidenceQuality.HIGH: 1.0,
}


@dataclass(frozen=True, slots=True)
class Evidence:
    """One observation, referenced by an opaque evidence ID (never raw secrets).

    `independence_key` groups observations sharing the same root measurement or
    underlying source. Multiple observations in one group receive diminishing credit.
    `fingerprint` can identify duplicates across auditor runs; when absent, a stable
    digest of non-sensitive metadata is generated. Evidence IDs must be unique.
    """
    evidence_id: str
    kind: EvidenceKind
    quality: EvidenceQuality = EvidenceQuality.MEDIUM
    independence_key: str = ""
    fingerprint: str = ""
    reproducible: bool = False
    controlled: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_id.strip():
            raise ValueError("evidence_id cannot be empty")
        if not isinstance(self.kind, EvidenceKind):
            raise TypeError("kind must be EvidenceKind")
        if not isinstance(self.quality, EvidenceQuality):
            raise TypeError("quality must be EvidenceQuality")
        if len(self.description) > 4096:
            raise ValueError("description is too long")

    def dedup_key(self) -> str:
        if self.fingerprint.strip():
            return self.fingerprint.strip()
        # ID is intentional here: independent observations may have identical labels.
        return sha256(f"{self.evidence_id}\0{self.kind.value}".encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class AssessmentInput:
    finding_id: str
    evidence: tuple[Evidence, ...]
    scope: ScopeStatus = ScopeStatus.UNKNOWN
    # True only if the auditor can attest that the observed effect is security-relevant.
    security_impact_demonstrated: bool = False
    # Independent controls must have been performed and passed.
    controls_passed: bool = False
    # E.g., unexpected WAF response, auth expiration, inconsistent server behavior.
    environment_unstable: bool = False

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("finding_id cannot be empty")
        if not isinstance(self.scope, ScopeStatus):
            raise TypeError("scope must be ScopeStatus")
        if not isinstance(self.evidence, tuple):
            raise TypeError("evidence must be a tuple")
        if any(not isinstance(item, Evidence) for item in self.evidence):
            raise TypeError("evidence must contain only Evidence instances")


@dataclass(frozen=True, slots=True)
class Assessment:
    finding_id: str
    score: int
    status: FindingStatus
    evidence_count: int
    independent_sources: int
    reasons: tuple[str, ...]
    limitations: tuple[str, ...]
    model_version: str = "muninn-confidence-v1"

    def as_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "score": self.score,
            "status": self.status.value,
            "evidence_count": self.evidence_count,
            "independent_sources": self.independent_sources,
            "reasons": list(self.reasons),
            "limitations": list(self.limitations),
            "model_version": self.model_version,
            "score_interpretation": "heuristic_priority_not_probability",
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.as_dict(), indent=indent, sort_keys=True)


class ConfidenceEngine:
    """Deterministic, conservative, bounded evidence scorer.

    A VALIDATED label requires: authorized scope, impact evidence, independent
    controls, reproducible controlled observation, and no contradictions.
    Merely setting booleans without supporting evidence does not validate.
    """

    VERSION = "muninn-confidence-v1"

    def assess(self, item: AssessmentInput) -> Assessment:
        seen_ids: set[str] = set()
        seen_fingerprints: set[str] = set()
        unique: list[Evidence] = []
        limitations: list[str] = []
        reasons: list[str] = []

        for ev in item.evidence:
            if ev.evidence_id in seen_ids:
                raise ValueError(f"duplicate evidence_id: {ev.evidence_id}")
            seen_ids.add(ev.evidence_id)
            key = ev.dedup_key()
            if key in seen_fingerprints:
                continue
            seen_fingerprints.add(key)
            unique.append(ev)

        if len(unique) < len(item.evidence):
            limitations.append(f"Ignored {len(item.evidence) - len(unique)} duplicate observations")

        # A source grouping is a claim made by the caller; it is not proof of independence.
        groups: dict[str, list[Evidence]] = {}
        for ev in unique:
            group_key = ev.independence_key.strip() or f"ungrouped:{ev.evidence_id}"
            groups.setdefault(group_key, []).append(ev)

        positive_total = 0.0
        negative_total = 0.0
        for group in groups.values():
            positives = sorted(
                (WEIGHTS[ev.kind] * QUALITY_MULTIPLIERS[ev.quality]
                 for ev in group if ev.kind != EvidenceKind.CONTRADICTION),
                reverse=True,
            )
            negatives = sorted(
                (abs(WEIGHTS[ev.kind]) * QUALITY_MULTIPLIERS[ev.quality]
                 for ev in group if ev.kind == EvidenceKind.CONTRADICTION),
                reverse=True,
            )
            # One source cannot manufacture unlimited confidence through repetitions.
            positive_total += sum(value * (0.25 ** i) for i, value in enumerate(positives))
            negative_total += sum(value * (0.5 ** i) for i, value in enumerate(negatives))

        has_contradiction = any(ev.kind == EvidenceKind.CONTRADICTION for ev in unique)
        has_impact = any(ev.kind == EvidenceKind.IMPACT and ev.controlled and ev.reproducible
                         for ev in unique)
        has_reproduction = any(ev.kind == EvidenceKind.REPRODUCTION and ev.controlled
                               and ev.reproducible for ev in unique)
        has_negative_control = any(ev.kind == EvidenceKind.NEGATIVE_CONTROL and ev.controlled
                                   for ev in unique)
        has_differential = any(ev.kind == EvidenceKind.DIFFERENTIAL and ev.controlled
                               for ev in unique)
        independent_positive_groups = {
            ev.independence_key.strip() or f"ungrouped:{ev.evidence_id}"
            for ev in unique if ev.kind != EvidenceKind.CONTRADICTION
        }

        score = round(max(0.0, min(100.0, positive_total - negative_total)))
        if item.environment_unstable:
            score = min(score, 35)
            limitations.append("Environment marked unstable; confidence capped")
        if item.scope != ScopeStatus.AUTHORIZED:
            score = min(score, 30)
            limitations.append(f"Scope is {item.scope.value}; validation prohibited")
        if not item.controls_passed:
            score = min(score, 60)
            limitations.append("Independent controls have not passed")
        if not item.security_impact_demonstrated:
            score = min(score, 65)
            limitations.append("Security impact has not been demonstrated")
        if not has_impact:
            score = min(score, 75)
            limitations.append("No controlled, reproducible impact evidence")
        if has_contradiction:
            score = min(score, 45)
            limitations.append("Contradictory evidence exists; manual reconciliation required")
        if not unique:
            limitations.append("No evidence provided")

        validation_ready = (
            item.scope == ScopeStatus.AUTHORIZED
            and not item.environment_unstable
            and not has_contradiction
            and item.security_impact_demonstrated
            and item.controls_passed
            and has_impact
            and has_reproduction
            and has_negative_control
            and has_differential
            and len(independent_positive_groups) >= 2
        )

        if validation_ready:
            # Strong validation is a categorical outcome; numeric score remains heuristic.
            score = max(score, 90)
            status = FindingStatus.VALIDATED
            reasons.append("Controlled, reproducible impact with differential, reproduction and negative controls")
        elif has_contradiction and negative_total > positive_total and not has_impact:
            status = FindingStatus.REFUTED
            reasons.append("Contradictory observations outweigh supporting evidence")
        elif not unique or item.environment_unstable or has_contradiction:
            status = FindingStatus.INCONCLUSIVE
            reasons.append("Insufficient or conflicting evidence")
        elif score >= 30 and len(independent_positive_groups) >= 2:
            status = FindingStatus.CORROBORATED
            reasons.append("Multiple distinct evidence groups support the hypothesis")
        else:
            status = FindingStatus.CANDIDATE
            reasons.append("Evidence suggests a candidate but does not establish exploitability")

        if item.scope == ScopeStatus.PROHIBITED:
            status = FindingStatus.INCONCLUSIVE
            reasons.append("Prohibited asset: do not perform active validation")
        if item.scope == ScopeStatus.UNKNOWN:
            status = FindingStatus.INCONCLUSIVE
            reasons.append("Authorization must be established before validation")

        return Assessment(
            finding_id=item.finding_id,
            score=score,
            status=status,
            evidence_count=len(unique),
            independent_sources=len(groups),
            reasons=tuple(reasons),
            limitations=tuple(limitations),
            model_version=self.VERSION,
        )


def assess_finding(
    finding_id: str,
    evidence: Iterable[Evidence],
    *,
    scope: ScopeStatus = ScopeStatus.UNKNOWN,
    security_impact_demonstrated: bool = False,
    controls_passed: bool = False,
    environment_unstable: bool = False,
) -> Assessment:
    """Convenience wrapper for audit modules."""
    return ConfidenceEngine().assess(AssessmentInput(
        finding_id=finding_id,
        evidence=tuple(evidence),
        scope=scope,
        security_impact_demonstrated=security_impact_demonstrated,
        controls_passed=controls_passed,
        environment_unstable=environment_unstable,
    ))


__all__ = [
    "Assessment", "AssessmentInput", "ConfidenceEngine", "Evidence",
    "EvidenceKind", "EvidenceQuality", "FindingStatus", "ScopeStatus",
    "assess_finding",
]
