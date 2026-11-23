"""Muninn passive HTTP request-smuggling evidence auditor.

Analyzes captured HTTP/1.x request bytes and externally verified parser outcomes.
No network traffic, payload generation, or active desynchronization testing.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
from typing import Callable, Iterable, Mapping
import json
import re
from urllib.parse import urlsplit

_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_CL = re.compile(rb"^[0-9]+$")


@dataclass(frozen=True)
class SmugglingCapture:
    url: str
    raw_request: bytes
    scenario: str = "captured_request"
    protocol: str = "http1"
    frontend_consumed_bytes: int | None = None
    backend_consumed_bytes: int | None = None
    parser_outcomes_trusted: bool = False
    isolated_test: bool = False


@dataclass(frozen=True)
class SmugglingConfig:
    max_captures: int = 10000
    max_request_bytes: int = 1_000_000
    max_header_bytes: int = 65536
    max_headers: int = 200
    max_findings: int = 5000


@dataclass(frozen=True)
class Finding:
    code: str
    confidence: str
    severity: str
    url_origin: str
    evidence_sha256: str
    description: str
    scenario: str


@dataclass(frozen=True)
class SmugglingReport:
    inspected: int
    skipped: int
    findings: tuple[Finding, ...]

    def to_json(self) -> str:
        return json.dumps({"inspected": self.inspected, "skipped": self.skipped,
                           "findings": [asdict(f) for f in self.findings]}, sort_keys=True)


class SmugglingAuditor:
    def __init__(self, config: SmugglingConfig | None = None):
        self.config = config or SmugglingConfig()
        if min(self.config.max_captures, self.config.max_request_bytes,
               self.config.max_header_bytes, self.config.max_headers,
               self.config.max_findings) < 1:
            raise ValueError("All limits must be positive")

    def analyze(self, captures: Iterable[SmugglingCapture], *,
                scope_check: Callable[[str], bool]) -> SmugglingReport:
        if not callable(scope_check):
            raise TypeError("scope_check callback is required")
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        inspected = skipped = 0
        for index, capture in enumerate(captures):
            if index >= self.config.max_captures:
                break
            if not isinstance(capture.raw_request, bytes):
                skipped += 1
                continue
            try:
                parsed_url = urlsplit(capture.url)
                if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
                    skipped += 1
                    continue
                if not scope_check(capture.url):
                    skipped += 1
                    continue
            except (ValueError, TypeError):
                skipped += 1
                continue
            if len(capture.raw_request) > self.config.max_request_bytes:
                skipped += 1
                continue
            inspected += 1
            origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
            digest = sha256(capture.raw_request).hexdigest()

            def add(code: str, description: str, confidence: str = "low",
                    severity: str = "review") -> None:
                if len(findings) >= self.config.max_findings:
                    return
                key = (code, digest, capture.scenario)
                if key in seen:
                    return
                seen.add(key)
                findings.append(Finding(code, confidence, severity, origin, digest,
                                        description, capture.scenario[:100]))

            raw = capture.raw_request
            boundary = raw.find(b"\r\n\r\n")
            if boundary == -1:
                add("INVALID_HEADER_BOUNDARY", "No standard CRLF header terminator")
                continue
            if boundary > self.config.max_header_bytes:
                add("HEADER_LIMIT_EXCEEDED", "Header section exceeds configured analysis limit")
                continue
            header_blob = raw[:boundary]
            lines = header_blob.split(b"\r\n")
            if not lines or not re.match(rb"^[A-Z]+ [^\r\n ]+ HTTP/1\.[01]$", lines[0]):
                add("INVALID_REQUEST_LINE", "Request line does not match expected HTTP/1.x form")
            headers: dict[bytes, list[bytes]] = {}
            if len(lines) - 1 > self.config.max_headers:
                add("HEADER_COUNT_EXCEEDED", "Header count exceeds configured analysis limit")
                continue
            for line in lines[1:]:
                if line.startswith((b" ", b"\t")):
                    add("OBSOLETE_LINE_FOLDING", "Header continuation line could be parsed inconsistently")
                    continue
                if b":" not in line:
                    add("MALFORMED_HEADER", "Header line lacks a colon")
                    continue
                name, value = line.split(b":", 1)
                if name != name.strip():
                    add("WHITESPACE_BEFORE_COLON", "Whitespace adjacent to header-name delimiter")
                if not _HEADER_NAME.fullmatch(name):
                    add("INVALID_HEADER_NAME", "Invalid HTTP header field name")
                normalized = name.strip().lower()
                headers.setdefault(normalized, []).append(value.strip(b" \t"))
            cls = headers.get(b"content-length", [])
            tes = headers.get(b"transfer-encoding", [])
            if len(cls) > 1:
                add("DUPLICATE_CONTENT_LENGTH", "Multiple Content-Length header fields")
            if any(not _CL.fullmatch(v) for v in cls):
                add("INVALID_CONTENT_LENGTH", "Content-Length is not a single decimal integer")
            elif len(set(cls)) > 1:
                add("CONFLICTING_CONTENT_LENGTH", "Different Content-Length values may cause parser disagreement",
                    "medium")
            if cls and tes:
                add("CL_TE_AMBIGUITY", "Both Content-Length and Transfer-Encoding are present", "medium")
            if len(tes) > 1:
                add("MULTIPLE_TRANSFER_ENCODING", "Multiple Transfer-Encoding fields require careful normalization")
            if tes:
                tokens = [part.strip().lower() for v in tes for part in v.split(b",")]
                if any(not t for t in tokens):
                    add("INVALID_TRANSFER_ENCODING", "Empty transfer-coding token")
                if b"chunked" in tokens and tokens[-1] != b"chunked":
                    add("NONFINAL_CHUNKED", "Chunked transfer coding is not final")
                if tokens.count(b"chunked") > 1:
                    add("REPEATED_CHUNKED", "Chunked transfer coding appears more than once")
                if any(b";" in t or b"\x00" in t for t in tokens):
                    add("SUSPICIOUS_TRANSFER_ENCODING", "Transfer-Encoding contains parameters or control bytes")
            if capture.protocol.lower() in ("h2", "http2", "http/2"):
                add("H2_CAPTURE_AS_HTTP1", "HTTP/2-labelled capture represented as HTTP/1 bytes; downgrade behavior requires independent evidence")
            if capture.parser_outcomes_trusted and capture.isolated_test:
                front, back = capture.frontend_consumed_bytes, capture.backend_consumed_bytes
                if (isinstance(front, int) and not isinstance(front, bool)
                        and isinstance(back, int) and not isinstance(back, bool)
                        and 0 <= front <= len(raw) and 0 <= back <= len(raw) and front != back):
                    add("VERIFIED_PARSER_DISAGREEMENT",
                        "Trusted isolated test recorded different frontend and backend message boundaries",
                        "high", "high")
        return SmugglingReport(inspected, skipped, tuple(findings))
