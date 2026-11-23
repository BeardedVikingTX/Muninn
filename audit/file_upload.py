"""Muninn file-upload security auditor (offline, non-executing).

Analyze authorized upload observations and optional retrieval observations. This
module never sends requests, creates executable payloads, or executes commands.
Findings are review indicators, not confirmed remote code execution.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from hashlib import sha256
from urllib.parse import urlsplit
import json
import re
from typing import Callable, Iterable, Mapping

EXECUTABLE_SUFFIXES = frozenset({"php", "phtml", "phar", "jsp", "jspx", "asp", "aspx", "ashx", "cgi", "pl", "py", "sh"})
IMAGE_MIME = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}
SIGNATURES = {"png": b"\x89PNG\r\n\x1a\n", "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff", "gif": (b"GIF87a", b"GIF89a"), "webp": b"RIFF"}
ACTIVE_TYPES = frozenset({"text/html", "application/xhtml+xml", "image/svg+xml", "application/javascript", "text/javascript"})


def _headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(k).lower().strip(): str(v).strip() for k, v in headers.items()}


def _safe_url(url: str) -> str:
    p = urlsplit(url)
    if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
        raise ValueError("Expected HTTP(S) URL without embedded credentials")
    return f"{p.scheme.lower()}://{p.hostname.lower()}" + (f":{p.port}" if p.port else "")


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def _suffixes(filename: str) -> tuple[str, ...]:
    name = filename.replace("\\", "/").rsplit("/", 1)[-1].lower().strip()
    return tuple(part for part in name.split(".")[1:] if part)


def _magic_matches(suffix: str, data: bytes) -> bool | None:
    if suffix not in SIGNATURES:
        return None
    if suffix == "webp":
        return data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP"
    signatures = SIGNATURES[suffix]
    if isinstance(signatures, bytes):
        signatures = (signatures,)
    return any(data.startswith(s) for s in signatures)


@dataclass(frozen=True)
class UploadObservation:
    endpoint: str
    filename: str
    declared_type: str
    content_prefix: bytes
    status: int
    accepted: bool
    response_headers: Mapping[str, str] | None = None
    retrieval_url: str | None = None
    retrieval_status: int | None = None
    retrieval_headers: Mapping[str, str] | None = None
    marker_present_on_retrieval: bool = False
    expected_image_only: bool = False
    scenario: str = "default"


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    confidence: str
    endpoint_origin: str
    evidence_id: str
    detail: str


@dataclass(frozen=True)
class AuditReport:
    analyzed: int
    skipped: int
    findings: tuple[Finding, ...]

    def to_json(self) -> str:
        return json.dumps({"analyzed": self.analyzed, "skipped": self.skipped,
                           "findings": [asdict(f) for f in self.findings]}, sort_keys=True)


class FileUploadAuditor:
    """Fail-closed, offline file-upload observation analyzer."""

    def __init__(self, *, max_observations: int = 10000, max_findings: int = 2000,
                 max_prefix_bytes: int = 4096):
        if min(max_observations, max_findings, max_prefix_bytes) <= 0:
            raise ValueError("Resource limits must be positive")
        self.max_observations = max_observations
        self.max_findings = max_findings
        self.max_prefix_bytes = max_prefix_bytes

    def analyze(self, observations: Iterable[UploadObservation], *,
                scope_check: Callable[[str], bool]) -> AuditReport:
        if not callable(scope_check):
            raise TypeError("scope_check must be callable")
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        analyzed = skipped = 0
        for index, obs in enumerate(observations):
            if index >= self.max_observations:
                break
            try:
                origin = _safe_url(obs.endpoint)
                if not scope_check(obs.endpoint):
                    skipped += 1
                    continue
                if obs.retrieval_url is not None:
                    _safe_url(obs.retrieval_url)
                    if not scope_check(obs.retrieval_url):
                        skipped += 1
                        continue
            except (ValueError, TypeError, OverflowError):
                skipped += 1
                continue
            except Exception:
                skipped += 1
                continue
            analyzed += 1
            evidence_id = _digest(f"{obs.scenario}|{obs.endpoint}|{obs.filename}")
            suffixes = _suffixes(obs.filename)
            ext = suffixes[-1] if suffixes else ""
            mime = obs.declared_type.lower().split(";", 1)[0].strip()
            prefix = obs.content_prefix[:self.max_prefix_bytes]
            retrieval = _headers(obs.retrieval_headers or {})
            response = _headers(obs.response_headers or {})

            def add(code: str, severity: str, confidence: str, detail: str) -> None:
                key = (code, evidence_id)
                if key not in seen and len(findings) < self.max_findings:
                    seen.add(key)
                    findings.append(Finding(code, severity, confidence, origin, evidence_id, detail))

            if not obs.accepted:
                continue
            if any(s in EXECUTABLE_SUFFIXES for s in suffixes):
                add("EXECUTABLE_EXTENSION_ACCEPTED", "high", "medium",
                    "An uploaded filename includes a server-executable extension; execution is not established")
            if obs.expected_image_only and ext not in IMAGE_MIME:
                add("NON_IMAGE_ACCEPTED", "medium", "high",
                    "An upload marked image-only accepted a filename without a recognized image extension")
            if ext in IMAGE_MIME:
                matches = _magic_matches(ext, prefix)
                if matches is False:
                    add("IMAGE_SIGNATURE_MISMATCH", "medium", "high",
                        "Accepted image extension does not match the observed file signature")
                expected_mime = IMAGE_MIME[ext]
                if mime != expected_mime:
                    add("IMAGE_MIME_MISMATCH", "low", "high",
                        "Declared content type differs from the filename's expected image media type")
            if obs.retrieval_status is not None and 200 <= obs.retrieval_status < 300:
                ct = retrieval.get("content-type", "").split(";", 1)[0].lower().strip()
                disposition = retrieval.get("content-disposition", "").lower()
                nosniff = "nosniff" in retrieval.get("x-content-type-options", "").lower()
                if ct in ACTIVE_TYPES and "attachment" not in disposition:
                    add("ACTIVE_CONTENT_SERVED_INLINE", "medium", "high",
                        "Retrieved upload is served inline with an active content type")
                if not nosniff and "attachment" not in disposition:
                    add("MISSING_NOSNIFF_ON_RETRIEVAL", "low", "high",
                        "Retrieved upload lacks X-Content-Type-Options: nosniff")
                if obs.marker_present_on_retrieval:
                    add("RETRIEVABLE_UPLOAD_MARKER", "info", "high",
                        "A harmless marker was observed in the retrieved upload; no code execution implied")
            if "location" in response:
                location = response["location"]
                if re.match(r"^https?://", location, flags=re.I):
                    try:
                        if _safe_url(location) != origin:
                            add("CROSS_ORIGIN_UPLOAD_REDIRECT", "low", "medium",
                                "Upload response redirects to a different origin")
                    except (ValueError, OverflowError):
                        pass
        return AuditReport(analyzed, skipped, tuple(findings))
