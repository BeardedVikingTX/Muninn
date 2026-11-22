"""Offline, conservative reporting for Muninn (Python 3.10+).

Accepts structured, sanitized findings, not raw HTTP messages. Writes JSON,
Markdown and HTML. Confidence is a heuristic, never a probability; reward
figures are optional program-configured ranges, never promised payments.

IMPORTANT: generic redaction cannot guarantee removal of all secrets or PII.
Only supply reviewed, sanitized summaries and opaque source identifiers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from html import escape
from pathlib import Path
from typing import Iterable, Mapping
import json
import os
import re
import tempfile

from core.confidence import Assessment, FindingStatus
from core.evidence import EvidenceRecord, redact_text

SCHEMA_VERSION = "muninn-report-v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MAX_TEXT = 4000


class ReportingError(ValueError):
    """Invalid report input or unsafe output destination."""


class Severity(str, Enum):
    INFO = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class Eligibility(str, Enum):
    UNKNOWN = "unknown"
    POTENTIALLY_ELIGIBLE = "potentially_eligible"
    INELIGIBLE = "ineligible"


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ReportingError(f"{label} must be an opaque safe identifier")
    return value


def _clean(value: str, label: str, *, required: bool = False) -> str:
    if not isinstance(value, str) or len(value) > _MAX_TEXT:
        raise ReportingError(f"{label} must be a string of at most {_MAX_TEXT} characters")
    if any(ord(c) < 32 and c not in '\n\t' for c in value):
        raise ReportingError(f"{label} contains control characters")
    result = redact_text(value).strip()
    if required and not result:
        raise ReportingError(f"{label} must not be empty")
    return result


@dataclass(frozen=True, slots=True)
class RewardRange:
    currency: str
    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Z]{3}", self.currency):
            raise ReportingError("currency must be ISO-style 3-letter uppercase code")
        if any(type(x) is not int or x < 0 for x in (self.minimum, self.maximum)) or self.minimum > self.maximum:
            raise ReportingError("invalid reward range")

    def as_dict(self) -> dict[str, object]:
        return {"currency": self.currency, "minimum": self.minimum, "maximum": self.maximum,
                "interpretation": "program_configured_range_not_expected_payout"}


@dataclass(frozen=True, slots=True)
class ReportFinding:
    finding_id: str
    title: str
    category: str
    severity: Severity
    assessment: Assessment
    summary: str
    impact: str = ""
    remediation: str = ""
    endpoint_label: str = ""  # Human-reviewed display label, NOT a raw URL.
    evidence: tuple[EvidenceRecord, ...] = field(default_factory=tuple)
    eligibility: Eligibility = Eligibility.UNKNOWN
    reward_range: RewardRange | None = None

    def __post_init__(self) -> None:
        _identifier(self.finding_id, "finding_id")
        _identifier(self.category, "category")
        if not isinstance(self.severity, Severity) or not isinstance(self.eligibility, Eligibility):
            raise ReportingError("invalid severity or eligibility")
        if not isinstance(self.assessment, Assessment) or self.assessment.finding_id != self.finding_id:
            raise ReportingError("assessment must match finding_id")
        if self.reward_range is not None and not isinstance(self.reward_range, RewardRange):
            raise ReportingError("reward_range must be RewardRange or None")
        if not isinstance(self.evidence, tuple) or any(not isinstance(e, EvidenceRecord) for e in self.evidence):
            raise ReportingError("evidence must be a tuple of EvidenceRecord")
        if len(self.evidence) > 1000:
            raise ReportingError("too many evidence records")
        if any(e.finding_id != self.finding_id for e in self.evidence):
            raise ReportingError("evidence belongs to another finding")
        ids = [e.evidence_id for e in self.evidence]
        if len(ids) != len(set(ids)):
            raise ReportingError("duplicate evidence identifiers")
        for name in ("title", "summary", "impact", "remediation", "endpoint_label"):
            _clean(getattr(self, name), name, required=name in ("title", "summary"))

    def as_dict(self) -> dict[str, object]:
        # No raw evidence bytes, excerpt contents, headers, or original URLs.
        return {
            "finding_id": self.finding_id,
            "title": _clean(self.title, "title"),
            "category": self.category,
            "severity": self.severity.value,
            "status": self.assessment.status.value,
            "confidence": {**self.assessment.as_dict(),
                           "reasons": [_clean(x, "confidence reason") for x in self.assessment.reasons],
                           "limitations": [_clean(x, "confidence limitation") for x in self.assessment.limitations]},
            "summary": _clean(self.summary, "summary"),
            "impact": _clean(self.impact, "impact"),
            "remediation": _clean(self.remediation, "remediation"),
            "endpoint_label": _clean(self.endpoint_label, "endpoint_label"),
            "evidence_refs": [{"evidence_id": e.evidence_id, "source_id": e.source_id,
                               "kind": e.kind.value, "excerpt_sha256": e.excerpt_sha256}
                              for e in self.evidence],
            "eligibility": self.eligibility.value,
            "reward_range": self.reward_range.as_dict() if self.reward_range else None,
        }


@dataclass(frozen=True, slots=True)
class ScanReport:
    scan_id: str
    program_id: str
    findings: tuple[ReportFinding, ...]
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    analyzed_transactions: int = 0
    skipped_transactions: int = 0
    scope_policy_verified: bool = False

    def __post_init__(self) -> None:
        _identifier(self.scan_id, "scan_id")
        _identifier(self.program_id, "program_id")
        if not isinstance(self.findings, tuple) or any(not isinstance(f, ReportFinding) for f in self.findings):
            raise ReportingError("findings must be a tuple of ReportFinding")
        if len(self.findings) > 100_000:
            raise ReportingError("too many findings")
        ids = [f.finding_id for f in self.findings]
        if len(ids) != len(set(ids)):
            raise ReportingError("duplicate finding identifiers")
        if any(type(x) is not int or x < 0 for x in (self.analyzed_transactions, self.skipped_transactions)):
            raise ReportingError("transaction counts must be nonnegative integers")
        if type(self.scope_policy_verified) is not bool:
            raise ReportingError("scope_policy_verified must be bool")
        try:
            dt = datetime.fromisoformat(self.created_at)
            if dt.tzinfo is None or dt.utcoffset() is None:
                raise ValueError
        except (ValueError, TypeError) as exc:
            raise ReportingError("created_at must be timezone-aware ISO-8601") from exc

    def as_dict(self) -> dict[str, object]:
        counts = {s.value: sum(f.assessment.status == s for f in self.findings) for s in FindingStatus}
        return {"schema_version": SCHEMA_VERSION, "scan_id": self.scan_id,
                "program_id": self.program_id, "created_at": self.created_at,
                "scope_policy_verified": self.scope_policy_verified,
                "analyzed_transactions": self.analyzed_transactions,
                "skipped_transactions": self.skipped_transactions,
                "finding_count": len(self.findings), "status_counts": counts,
                "findings": [f.as_dict() for f in sorted(self.findings, key=lambda x: x.finding_id)],
                "disclaimer": "Automated observations require human review. Scores are not probabilities. Rewards are not guaranteed."}


def render_json(report: ScanReport) -> str:
    return json.dumps(report.as_dict(), ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def _md(value: str) -> str:
    # Keep arbitrary user text out of Markdown syntax and raw HTML.
    value = escape(value, quote=False)
    for c in ("\\", "`", "*", "_", "[", "]", "<", ">", "|"):
        value = value.replace(c, "\\" + c)
    return value.replace("\n", "  \n")


def render_markdown(report: ScanReport) -> str:
    data = report.as_dict()
    lines = ["# Muninn Security Analysis", "", f"Scan: `{report.scan_id}`  ",
             f"Program: `{report.program_id}`  ", f"Generated: `{report.created_at}`", "",
             f"Transactions analyzed: {report.analyzed_transactions}; skipped: {report.skipped_transactions}.",
             f"Scope policy verified: {'yes' if report.scope_policy_verified else 'no'}.", "",
             "**Automated findings require human review. Confidence scores are heuristics, not probabilities; rewards are not guaranteed.**", ""]
    for f in sorted(report.findings, key=lambda x: x.finding_id):
        d = f.as_dict()
        lines.extend([f"## {_md(d['title'])} (`{f.finding_id}`)", "",
                      f"Category: `{f.category}` · Severity: `{f.severity.value}` · Status: `{f.assessment.status.value}` · Confidence: `{f.assessment.score}/100`", "",
                      f"**Summary:** {_md(d['summary'])}", ""])
        for label, key in (("Impact", "impact"), ("Remediation", "remediation"), ("Endpoint label", "endpoint_label")):
            if d[key]:
                lines.extend([f"**{label}:** {_md(d[key])}", ""])
        lines.extend([f"**Eligibility:** `{f.eligibility.value}`", ""])
        if f.reward_range:
            r = f.reward_range
            lines.extend([f"Configured reward range (not a payout prediction): {r.currency} {r.minimum:,}–{r.maximum:,}", ""])
        if f.evidence:
            lines.append("**Evidence references:** " + ", ".join(f"`{e.evidence_id}`" for e in f.evidence))
            lines.append("")
        if f.assessment.limitations:
            lines.extend(["**Limitations:** " + _md("; ".join(d["confidence"]["limitations"])), ""])
    if not report.findings:
        lines.extend(["No findings were recorded. This does not establish that the target is secure.", ""])
    return "\n".join(lines).rstrip() + "\n"


def render_html(report: ScanReport) -> str:
    # HTML output uses escaped values from sanitized, structured report data.
    data = report.as_dict()
    parts = ["<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">',
             '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;">',
             '<title>Muninn Security Analysis</title>',
             '<style>body{font:16px system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;line-height:1.6}article{border:1px solid #aaa;border-radius:8px;padding:1rem;margin:1rem 0}small{color:#555}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>',
             '</head><body><h1>Muninn Security Analysis</h1>',
             f'<p>Scan: <code>{escape(report.scan_id)}</code> · Program: <code>{escape(report.program_id)}</code></p>',
             f'<p>Analyzed: {report.analyzed_transactions} · Skipped: {report.skipped_transactions} · Scope policy verified: {"yes" if report.scope_policy_verified else "no"}</p>',
             '<p><strong>Human review required. Confidence is heuristic, not probability. No payout is guaranteed.</strong></p>']
    for f in sorted(report.findings, key=lambda x: x.finding_id):
        d = f.as_dict()
        parts.extend(["<article>", f'<h2>{escape(d["title"])}</h2>',
                      f'<small>{escape(f.finding_id)} · {escape(f.category)} · {f.severity.value} · {f.assessment.status.value} · {f.assessment.score}/100</small>',
                      f'<p><strong>Summary:</strong> {escape(d["summary"])}</p>'])
        for label, key in (("Impact", "impact"), ("Remediation", "remediation"), ("Endpoint", "endpoint_label")):
            if d[key]:
                parts.append(f'<p><strong>{label}:</strong> {escape(d[key])}</p>')
        parts.append(f'<p>Eligibility: {f.eligibility.value}</p>')
        if f.reward_range:
            r = f.reward_range
            parts.append(f'<p>Configured reward range (not a payout prediction): {r.currency} {r.minimum:,}–{r.maximum:,}</p>')
        if f.evidence:
            parts.append('<p>Evidence IDs: ' + ', '.join(escape(e.evidence_id) for e in f.evidence) + '</p>')
        if f.assessment.limitations:
            parts.append('<p>Limitations: ' + escape('; '.join(d['confidence']['limitations'])) + '</p>')
        parts.append('</article>')
    if not report.findings:
        parts.append('<p>No findings recorded; this does not establish security.</p>')
    parts.append('</body></html>\n')
    return '\n'.join(parts)


def _private_atomic_write(directory: Path, filename: str, content: str) -> Path:
    """Write within a private directory; refuse symlinked output directories/files.

    This is suitable for a user-owned workspace, not a hostile concurrent filesystem.
    """
    if directory.is_symlink():
        raise ReportingError("output directory must not be a symlink")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise ReportingError("invalid output directory")
    if os.name == "posix":
        os.chmod(directory, 0o700)
    destination = directory / filename
    if destination.is_symlink():
        raise ReportingError("refusing to replace symlink")
    tmp_name = None
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=".muninn-", suffix=".tmp", dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            if os.name == "posix":
                os.fchmod(handle.fileno(), 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, destination)
        tmp_name = None
        return destination
    finally:
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass


def write_report(report: ScanReport, output_directory: str | Path) -> Mapping[str, Path]:
    """Render and save a report in three formats; no HTTP requests or AI calls.

    The output folder must be private and controlled by the current user.
    """
    if not isinstance(report, ScanReport):
        raise TypeError("report must be ScanReport")
    directory = Path(output_directory)
    if directory.exists() and directory.is_symlink():
        raise ReportingError("output directory must not be a symlink")
    rendered = {"json": render_json(report), "md": render_markdown(report), "html": render_html(report)}
    return {ext: _private_atomic_write(directory, f"report.{ext}", content) for ext, content in rendered.items()}
