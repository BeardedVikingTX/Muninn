"""Muninn offline XSS evidence auditor.

No network I/O, JavaScript execution, or payload deployment. Findings are
heuristics unless backed by independent trusted browser/test evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
from html.parser import HTMLParser
import html
import json
import re
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit


class XSSInputError(ValueError):
    """Invalid or unbounded capture data."""


@dataclass(frozen=True)
class XSSConfig:
    max_captures: int = 10000
    max_findings: int = 3000
    max_body_chars: int = 2_000_000
    max_marker_chars: int = 128
    max_js_chars: int = 2_000_000

    def __post_init__(self):
        for name, value in asdict(self).items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class XSSCapture:
    url: str
    response_body: str = ""
    response_headers: Mapping[str, str] = field(default_factory=dict)
    content_type: str = "text/html"
    marker: str = ""
    scenario: str = ""
    stored: bool = False
    independent_session: bool = False
    js_source: str = ""
    # Only set these from independently verified, authorized test fixtures.
    browser_executed: bool = False
    browser_evidence_trusted: bool = False
    execution_provenance: str = ""


@dataclass(frozen=True)
class XSSFinding:
    code: str
    category: str
    confidence: str
    severity: str
    url_origin: str
    evidence_hash: str
    description: str
    recommendation: str
    scenario_hash: str


@dataclass(frozen=True)
class XSSReport:
    captures_analyzed: int
    findings: tuple[XSSFinding, ...]

    def to_json(self) -> str:
        return json.dumps({
            "captures_analyzed": self.captures_analyzed,
            "findings": [asdict(f) for f in self.findings],
        }, sort_keys=True, separators=(",", ":"))


class _HTMLContextParser(HTMLParser):
    """Collect text/attribute occurrences without executing content."""

    def __init__(self, marker: str):
        super().__init__(convert_charrefs=True)
        self.marker = marker
        self.stack: list[str] = []
        self.contexts: set[str] = set()

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        for name, value in attrs:
            if value is None or self.marker not in value:
                continue
            name = name.lower()
            if name.startswith("on"):
                self.contexts.add("event_handler_attribute")
            elif name in {"href", "src", "action", "formaction", "xlink:href"}:
                self.contexts.add("url_attribute")
            elif name == "style":
                self.contexts.add("style_attribute")
            else:
                self.contexts.add("html_attribute")
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()

    def handle_endtag(self, tag):
        if tag in self.stack:
            while self.stack:
                popped = self.stack.pop()
                if popped == tag:
                    break

    def handle_data(self, data):
        if self.marker not in data:
            return
        if "script" in self.stack:
            self.contexts.add("script_text")
        elif "style" in self.stack:
            self.contexts.add("style_text")
        else:
            self.contexts.add("html_text")


_DOM_SOURCES = re.compile(r"\b(?:location\.(?:hash|search|href)|document\.(?:URL|referrer|cookie)|window\.name|URLSearchParams\s*\()")
_DOM_SINKS = {
    "innerHTML": re.compile(r"\.innerHTML\s*="),
    "outerHTML": re.compile(r"\.outerHTML\s*="),
    "insertAdjacentHTML": re.compile(r"\.insertAdjacentHTML\s*\("),
    "document.write": re.compile(r"\bdocument\.write(?:ln)?\s*\("),
    "eval": re.compile(r"\beval\s*\("),
    "Function": re.compile(r"\bnew\s+Function\s*\("),
    "setTimeout_string": re.compile(r"\bsetTimeout\s*\(\s*['\"]"),
}


def _fingerprint(value: str) -> str:
    return sha256(value.encode("utf-8", errors="replace")).hexdigest()[:20]


def _origin(url: str) -> str:
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError
        port = parsed.port
        if port is not None and not (1 <= port <= 65535):
            raise ValueError
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        return f"{parsed.scheme}://{host}" + (f":{port}" if port else "")
    except (ValueError, TypeError) as exc:
        raise XSSInputError("capture URL must be a valid HTTP(S) URL") from exc


def _headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


class XSSAuditor:
    def __init__(self, config: XSSConfig | None = None):
        self.config = config or XSSConfig()

    def analyze(self, captures: Iterable[XSSCapture], *, scope_check: Callable[[str], bool]) -> XSSReport:
        if not callable(scope_check):
            raise XSSInputError("scope_check callback is required")
        findings: list[XSSFinding] = []
        seen: set[tuple[str, str, str]] = set()
        count = 0

        def add(capture: XSSCapture, origin: str, code: str, category: str,
                confidence: str, severity: str, description: str, recommendation: str,
                evidence: str):
            key = (code, capture.url, capture.scenario)
            if key in seen or len(findings) >= self.config.max_findings:
                return
            seen.add(key)
            findings.append(XSSFinding(
                code=code, category=category, confidence=confidence,
                severity=severity, url_origin=origin,
                evidence_hash=_fingerprint(evidence), description=description,
                recommendation=recommendation,
                scenario_hash=_fingerprint(capture.scenario),
            ))

        for capture in captures:
            if count >= self.config.max_captures:
                raise XSSInputError("capture count exceeds configured limit")
            if not isinstance(capture, XSSCapture):
                raise XSSInputError("all captures must be XSSCapture instances")
            origin = _origin(capture.url)
            if not scope_check(capture.url):
                raise XSSInputError("capture outside authorized scope")
            if not isinstance(capture.response_body, str) or not isinstance(capture.js_source, str) or not isinstance(capture.marker, str):
                raise XSSInputError("body, JS source, and marker must be strings")
            if len(capture.response_body) > self.config.max_body_chars or len(capture.js_source) > self.config.max_js_chars:
                raise XSSInputError("capture body exceeds configured limit")
            if len(capture.marker) > self.config.max_marker_chars:
                raise XSSInputError("marker exceeds configured limit")
            count += 1
            headers = _headers(capture.response_headers)
            ctype = headers.get("content-type", capture.content_type).lower()
            csp = headers.get("content-security-policy", "")

            if capture.marker and capture.marker in capture.response_body:
                contexts: set[str] = set()
                if "html" in ctype or "xhtml" in ctype:
                    parser = _HTMLContextParser(capture.marker)
                    try:
                        parser.feed(capture.response_body)
                        parser.close()
                        contexts = parser.contexts
                    except (ValueError, AssertionError):
                        contexts = set()
                elif "javascript" in ctype or "ecmascript" in ctype:
                    contexts = {"script_text"}
                elif "json" in ctype or "text/plain" in ctype:
                    contexts = {"non_executable_response"}
                else:
                    contexts = {"unknown_response_context"}
                for context in sorted(contexts):
                    add(capture, origin, f"REFLECTION_{context.upper()}",
                        "stored_xss" if capture.stored else "reflected_xss",
                        "low", "info" if context in {"html_text", "non_executable_response", "unknown_response_context"} else "low",
                        f"Controlled marker reflected in {context}; browser execution is not established.",
                        "Review output encoding for this context and verify using an isolated browser fixture.",
                        context + capture.marker)
                if capture.stored and capture.independent_session:
                    add(capture, origin, "STORED_CROSS_SESSION_REFLECTION", "stored_xss",
                        "medium", "medium",
                        "Controlled marker observed in an independent session after storage; execution is unverified.",
                        "Verify persistence, ownership, output context, and execution in an authorized browser fixture.",
                        capture.marker + "stored")

            if capture.js_source:
                sources = bool(_DOM_SOURCES.search(capture.js_source))
                for sink, regex in _DOM_SINKS.items():
                    if regex.search(capture.js_source):
                        add(capture, origin, f"DOM_SINK_{sink.upper().replace('.', '_')}", "dom_xss",
                            "low", "low",
                            f"Potential DOM execution sink ({sink}) detected; untrusted data flow is not proven."
                            + (" Potential input source also present." if sources else ""),
                            "Perform AST-based source-to-sink tracing and verify sanitizer behavior.", sink + capture.js_source[:2048])

            if csp:
                if re.search(r"(?:^|[;\s])(?:script-src|default-src)\s+[^;]*'unsafe-inline'", csp, re.I):
                    add(capture, origin, "CSP_UNSAFE_INLINE", "defense_in_depth", "low", "info",
                        "CSP allows unsafe-inline for a script-related directive; this does not prove XSS.",
                        "Review CSP against application needs and prefer nonces or hashes.", csp)
                if re.search(r"(?:^|[;\s])(?:script-src|default-src)\s+[^;]*'unsafe-eval'", csp, re.I):
                    add(capture, origin, "CSP_UNSAFE_EVAL", "defense_in_depth", "low", "info",
                        "CSP permits unsafe-eval in a script-related directive.",
                        "Remove unsafe-eval where feasible and audit dynamic code evaluation.", csp)

            if capture.browser_executed and capture.browser_evidence_trusted and capture.execution_provenance.strip():
                add(capture, origin, "TRUSTED_BROWSER_EXECUTION", "stored_xss" if capture.stored else "xss",
                    "high", "high",
                    "Trusted external browser fixture reports script execution in the tested security context.",
                    "Preserve independent browser evidence and confirm exploit preconditions and authorization scope.",
                    capture.execution_provenance)

        return XSSReport(captures_analyzed=count, findings=tuple(findings))
