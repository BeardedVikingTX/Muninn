"""Muninn passive account-recovery audit (Python 3.10+, stdlib only).

Inspects previously captured HTTPTransaction objects. NEVER sends requests,
initiates recovery, extracts tokens, guesses accounts, or asserts a vulnerability.
Observations are leads requiring authorized, controlled verification.

Use scope_engine to filter captures before calling analyze(); a Burp export may
include third-party traffic. Do not persist raw captured messages in reports.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Iterable
from urllib.parse import urlsplit, parse_qsl
import re

from core.http_models import HTTPTransaction

MAX_TRANSACTIONS = 100_000
MAX_BODY_INSPECT = 128 * 1024
MAX_OBSERVATIONS = 10_000
MAX_GROUPS = 10_000
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_RECOVERY_PATH = re.compile(r"(?:forgot|reset|recover|recovery|password[-_]?reset|magic[-_]?link|verify[-_]?email|account[-_]?unlock)", re.I)
_SENSITIVE_BODY = re.compile(rb'(?i)(?:reset[_-]?token|recovery[_-]?code|verification[_-]?code|magic[_-]?link|one[_-]?time[_-]?password)')
_TOKEN_IN_URL = re.compile(r"(?:token|code|otp|secret|key|password|reset|verify)", re.I)


class RecoveryAuditError(ValueError):
    """Invalid or excessive input; error messages exclude captured data."""


@dataclass(frozen=True, slots=True)
class RecoveryObservation:
    code: str
    source_id: str
    confidence: str
    description: str
    recommendation: str
    related_source_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.source_id) or any(not _ID.fullmatch(x) for x in self.related_source_ids):
            raise RecoveryAuditError("invalid source identifier")

    def safe_summary(self) -> dict[str, object]:
        return {"code": self.code, "source_id": self.source_id,
                "confidence": self.confidence, "description": self.description,
                "recommendation": self.recommendation,
                "related_source_ids": list(self.related_source_ids)}


@dataclass(frozen=True, slots=True)
class RecoveryAuditReport:
    analyzed: int
    recovery_candidates: int
    observations: tuple[RecoveryObservation, ...] = field(default_factory=tuple)
    skipped: int = 0

    def safe_summary(self) -> dict[str, object]:
        counts: dict[str, int] = {}
        for o in self.observations:
            counts[o.code] = counts.get(o.code, 0) + 1
        return {"analyzed": self.analyzed, "recovery_candidates": self.recovery_candidates,
                "skipped": self.skipped, "observation_count": len(self.observations),
                "observation_codes": dict(sorted(counts.items()))}


class AccountRecoveryAuditor:
    """Bounded, deterministic, read-only recovery-flow analyzer.

    Response similarity comparisons are deliberately restricted to requests
    with the same method, host and path, and are NOT enumeration findings.
    """

    def __init__(self, *, max_transactions: int = MAX_TRANSACTIONS,
                 max_observations: int = MAX_OBSERVATIONS,
                 inspect_body_bytes: int = MAX_BODY_INSPECT) -> None:
        if not all(type(x) is int and x > 0 for x in (max_transactions, max_observations, inspect_body_bytes)):
            raise RecoveryAuditError("limits must be positive integers")
        if max_transactions > MAX_TRANSACTIONS or max_observations > MAX_OBSERVATIONS or inspect_body_bytes > MAX_BODY_INSPECT:
            raise RecoveryAuditError("limits exceed hard caps")
        self.max_transactions = max_transactions
        self.max_observations = max_observations
        self.inspect_body_bytes = inspect_body_bytes

    def analyze(self, transactions: Iterable[HTTPTransaction]) -> RecoveryAuditReport:
        observations: list[RecoveryObservation] = []
        analyzed = candidates = skipped = 0
        # Track only bounded, opaque metadata; no identifier values or bodies.
        groups: dict[tuple[str, str, str], list[tuple[str, int, str]]] = {}

        def emit(code: str, tx: HTTPTransaction, description: str, recommendation: str,
                 confidence: str = "informational", related: tuple[str, ...] = ()) -> None:
            if len(observations) >= self.max_observations:
                raise RecoveryAuditError("observation limit exceeded")
            observations.append(RecoveryObservation(code, tx.source_id, confidence,
                                                     description, recommendation, related))

        for tx in transactions:
            if analyzed >= self.max_transactions:
                raise RecoveryAuditError("transaction limit exceeded")
            if not isinstance(tx, HTTPTransaction):
                raise RecoveryAuditError("expected HTTPTransaction")
            analyzed += 1
            request = tx.request
            try:
                # Prefer absolute source URL from Burp; otherwise use the request target.
                parts = urlsplit(request.source_url or request.target)
                path = parts.path or "/"
                host = (parts.hostname or "").lower()
                if not host:
                    host_header = request.headers.get("Host") or ""
                    # Never group on a malformed or ambiguous host header.
                    if re.fullmatch(r"[A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?", host_header):
                        host = host_header.lower()
            except ValueError:
                skipped += 1
                continue
            if not _RECOVERY_PATH.search(path):
                skipped += 1
                continue
            candidates += 1
            response = tx.response
            if response is None:
                emit("MISSING_RESPONSE", tx, "Recovery request has no captured response.",
                     "Capture a complete authorized baseline before assessing behavior.")
                continue

            cache_control = ",".join(response.headers.get_all("Cache-Control")).lower()
            if not any(flag in cache_control for flag in ("no-store", "private")):
                emit("CACHE_POLICY_REVIEW", tx,
                     "Recovery response lacks an explicit no-store or private cache directive.",
                     "Review whether the response contains sensitive recovery state and requires no-store.")

            if response.headers.get("Referrer-Policy") is None:
                emit("REFERRER_POLICY_REVIEW", tx,
                     "Recovery response does not declare a Referrer-Policy.",
                     "Review whether recovery URLs can leak via referrers; consider no-referrer.")

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if location:
                    try:
                        dest = urlsplit(location)
                        if dest.query and any(_TOKEN_IN_URL.search(k) for k, _ in parse_qsl(dest.query, keep_blank_values=True, max_num_fields=256)):
                            emit("REDIRECT_QUERY_SECRET_REVIEW", tx,
                                 "Recovery redirect has a credential-like query parameter name.",
                                 "Review URL-token exposure, logging, browser history and referrer behavior.")
                        if dest.hostname and host and dest.hostname.lower() != host:
                            emit("CROSS_HOST_REDIRECT_REVIEW", tx,
                                 "Recovery flow redirects to a different hostname.",
                                 "Verify the redirect destination is intended and trusted.")
                    except ValueError:
                        emit("MALFORMED_REDIRECT", tx,
                             "Recovery redirect URL could not be parsed safely.",
                             "Inspect redirect handling in an authorized environment.")

            for cookie in response.headers.get_all("Set-Cookie")[:32]:
                # Do not retain or display cookie names or values.
                attributes = {x.strip().split("=", 1)[0].lower() for x in cookie.split(";")[1:]}
                missing = tuple(flag for flag in ("secure", "httponly", "samesite") if flag not in attributes)
                if missing:
                    emit("COOKIE_FLAGS_REVIEW", tx,
                         "A cookie set by a recovery response lacks one or more recommended attributes.",
                         "Review Secure, HttpOnly and SameSite as appropriate for the cookie's purpose.")

            content_type = (response.headers.get("Content-Type") or "").lower()
            if ("text/" in content_type or "json" in content_type or "html" in content_type) and len(response.body) <= self.inspect_body_bytes:
                if _SENSITIVE_BODY.search(response.body):
                    emit("RECOVERY_MATERIAL_IN_BODY_REVIEW", tx,
                         "Recovery response contains a credential-like field label.",
                         "Review whether any sensitive recovery material is exposed to the wrong party.")

            # Only metadata, never user identifiers or parameter values.
            if request.method.upper() in {"POST", "PUT", "PATCH"} and host:
                group = (host, path, request.method.upper())
                if group not in groups and len(groups) >= MAX_GROUPS:
                    raise RecoveryAuditError("group limit exceeded")
                # Limited signature: status + body length + digest; a change is not a vulnerability.
                signature = sha256(response.body).hexdigest()[:16]
                group_items = groups.setdefault(group, [])
                if len(group_items) < 16:
                    group_items.append((tx.source_id, response.status_code, signature))

        # Report response differences as investigation leads, never as user enumeration.
        for items in groups.values():
            if len(items) < 2:
                continue
            distinct = {(status, digest) for _, status, digest in items}
            if len(distinct) > 1:
                source_id = items[0][0]
                if len(observations) >= self.max_observations:
                    raise RecoveryAuditError("observation limit exceeded")
                observations.append(RecoveryObservation(
                    "RECOVERY_RESPONSE_VARIATION", source_id, "informational",
                    "Captured recovery responses for the same endpoint differ.",
                    "Compare controlled authorized baselines; dynamic content alone may explain differences.",
                    tuple(item[0] for item in items[1:8])))

        observations.sort(key=lambda o: (o.source_id, o.code, o.related_source_ids))
        return RecoveryAuditReport(analyzed, candidates, tuple(observations), skipped)


def analyze_account_recovery(transactions: Iterable[HTTPTransaction]) -> RecoveryAuditReport:
    """Convenience entry point; passive and offline."""
    return AccountRecoveryAuditor().analyze(transactions)
