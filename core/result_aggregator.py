"""Muninn offline result aggregation (Python >=3.10).

Combines already-reviewed ReportFinding/ScanReport objects without running tests,
re-scoring confidence, guessing vulnerability identity, or reading raw HTTP data.
Explicit finding_id is the only deduplication key. Conflicting claims fail closed.
The output remains subject to human review and independent scope verification.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
from typing import Iterable
import json
import re

from core.reporting import ReportFinding, ScanReport

__all__ = ["ResultAggregator", "AggregationError", "AggregationResult", "AggregationStats"]

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MAX_REPORTS = 1000
_MAX_FINDINGS = 100000
_MAX_EVIDENCE = 100000


class AggregationError(ValueError):
    """Invalid or conflicting sanitized results (never includes raw field values)."""


@dataclass(frozen=True, slots=True)
class AggregationStats:
    input_reports: int
    input_findings: int
    unique_findings: int
    duplicate_observations: int
    unique_evidence: int
    analyzed_transactions: int
    skipped_transactions: int
    status_counts: tuple[tuple[str, int], ...]
    severity_counts: tuple[tuple[str, int], ...]

    def safe_summary(self) -> dict[str, object]:
        return {
            "input_reports": self.input_reports,
            "input_findings": self.input_findings,
            "unique_findings": self.unique_findings,
            "duplicate_observations": self.duplicate_observations,
            "unique_evidence": self.unique_evidence,
            "analyzed_transactions": self.analyzed_transactions,
            "skipped_transactions": self.skipped_transactions,
            "status_counts": dict(self.status_counts),
            "severity_counts": dict(self.severity_counts),
        }


@dataclass(frozen=True, slots=True)
class AggregationResult:
    report: ScanReport
    stats: AggregationStats
    source_scan_ids: tuple[str, ...]

    def safe_summary(self) -> dict[str, object]:
        return {"scan_id": self.report.scan_id, "program_id": self.report.program_id,
                "scope_policy_verified": self.report.scope_policy_verified,
                "source_scan_count": len(self.source_scan_ids), **self.stats.safe_summary()}


def _stable(value: object) -> str:
    """Canonical representation of already sanitized reporting model data."""
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _core(finding: ReportFinding) -> dict[str, object]:
    # Keep confidence fixed. Never increase confidence merely by counting duplicates.
    data = finding.as_dict()
    data.pop("evidence_refs")
    return data


class ResultAggregator:
    """Merge bounded, sanitized reports for one program.

    Identical finding IDs across scans indicate the *same* finding only when
    every non-evidence claim agrees. Different IDs are never auto-merged.
    Evidence IDs may be shared only when their complete metadata matches.
    Scan transaction totals are sums and can double-count overlapping captures.
    """

    def __init__(self, *, max_reports: int = _MAX_REPORTS,
                 max_findings: int = _MAX_FINDINGS,
                 max_evidence: int = _MAX_EVIDENCE):
        for label, value, ceiling in (("max_reports", max_reports, _MAX_REPORTS),
                                      ("max_findings", max_findings, _MAX_FINDINGS),
                                      ("max_evidence", max_evidence, _MAX_EVIDENCE)):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise AggregationError(f"{label} must be a positive bounded integer")
        self.max_reports = max_reports
        self.max_findings = max_findings
        self.max_evidence = max_evidence

    def aggregate(self, reports: Iterable[ScanReport], *, scan_id: str,
                  program_id: str | None = None) -> AggregationResult:
        if not isinstance(scan_id, str) or not _ID.fullmatch(scan_id):
            raise AggregationError("scan_id must be an opaque safe identifier")
        if program_id is not None and (not isinstance(program_id, str) or not _ID.fullmatch(program_id)):
            raise AggregationError("program_id must be an opaque safe identifier")
        if isinstance(reports, (str, bytes)):
            raise AggregationError("reports must be an iterable of ScanReport")
        try:
            iterator = iter(reports)
        except TypeError as exc:
            raise AggregationError("reports must be iterable") from exc

        sources: set[str] = set()
        findings: dict[str, ReportFinding] = {}
        evidence_maps: dict[str, dict[str, object]] = {}
        input_count = duplicates = analyzed = skipped = report_count = evidence_count = 0
        all_scoped = True
        chosen_program = program_id
        for report in iterator:
            report_count += 1
            if report_count > self.max_reports:
                raise AggregationError("report limit exceeded")
            if not isinstance(report, ScanReport):
                raise AggregationError("input must contain only ScanReport instances")
            if report.scan_id in sources:
                raise AggregationError("duplicate source scan identifier")
            sources.add(report.scan_id)
            if chosen_program is None:
                chosen_program = report.program_id
            if report.program_id != chosen_program:
                raise AggregationError("cross-program aggregation prohibited")
            all_scoped = all_scoped and report.scope_policy_verified
            analyzed += report.analyzed_transactions
            skipped += report.skipped_transactions
            for finding in report.findings:
                input_count += 1
                if input_count > self.max_findings:
                    raise AggregationError("finding limit exceeded")
                key = finding.finding_id
                if key not in findings:
                    findings[key] = finding
                    evidence_maps[key] = {e.evidence_id: e for e in finding.evidence}
                    evidence_count += len(finding.evidence)
                else:
                    if _stable(_core(findings[key])) != _stable(_core(finding)):
                        raise AggregationError("conflicting claims for a finding identifier")
                    duplicates += 1
                    target = evidence_maps[key]
                    for ev in finding.evidence:
                        if ev.evidence_id in target:
                            if _stable(target[ev.evidence_id].as_dict()) != _stable(ev.as_dict()):
                                raise AggregationError("conflicting evidence identifier")
                        else:
                            target[ev.evidence_id] = ev
                            evidence_count += 1
                if evidence_count > self.max_evidence:
                    raise AggregationError("evidence limit exceeded")
        if not sources:
            raise AggregationError("at least one source report is required")
        if scan_id in sources:
            raise AggregationError("output scan_id must differ from source scan identifiers")

        merged: list[ReportFinding] = []
        for fid in sorted(findings):
            base = findings[fid]
            # Preserve all evidence refs while keeping the original assessment.
            from dataclasses import replace
            merged.append(replace(base, evidence=tuple(evidence_maps[fid][eid]
                                                        for eid in sorted(evidence_maps[fid]))))
        combined = ScanReport(scan_id=scan_id, program_id=chosen_program,
                              findings=tuple(merged), analyzed_transactions=analyzed,
                              skipped_transactions=skipped, scope_policy_verified=all_scoped)
        status = Counter(f.assessment.status.value for f in merged)
        severity = Counter(f.severity.value for f in merged)
        stats = AggregationStats(report_count, input_count, len(merged), duplicates,
                                 evidence_count, analyzed, skipped,
                                 tuple(sorted(status.items())), tuple(sorted(severity.items())))
        return AggregationResult(combined, stats, tuple(sorted(sources)))
