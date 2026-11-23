"""Muninn passive JavaScript intelligence auditor.

Analyzes JavaScript source collected from authorized targets. Does not fetch URLs,
execute JavaScript, validate credentials, or replay requests. Findings intentionally
exclude secret values and raw source snippets.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit
import json
import re


@dataclass(frozen=True)
class JSAsset:
    url: str
    source: str
    content_type: str = "application/javascript"


@dataclass(frozen=True)
class JSFinding:
    rule_id: str
    severity: str
    confidence: str
    asset_id: str
    line: int
    description: str
    evidence_hash: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class JSReport:
    assets_seen: int
    assets_analyzed: int
    skipped: int
    findings: tuple[JSFinding, ...]

    def to_dict(self) -> dict:
        return {
            "assets_seen": self.assets_seen,
            "assets_analyzed": self.assets_analyzed,
            "skipped": self.skipped,
            "findings": [asdict(f) for f in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class JSConfig:
    max_assets: int = 5000
    max_asset_bytes: int = 2_000_000
    max_findings: int = 5000
    max_matches_per_rule_per_asset: int = 100
    include_low_confidence: bool = True

    def __post_init__(self) -> None:
        if min(self.max_assets, self.max_asset_bytes, self.max_findings,
               self.max_matches_per_rule_per_asset) < 1:
            raise ValueError("limits must be positive")


# Patterns identify possible secret material; matching values are NEVER reported.
_SECRET_RULES = (
    ("PRIVATE_KEY", "critical", "high", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("AWS_ACCESS_KEY", "high", "medium", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GITHUB_TOKEN", "high", "medium", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("SLACK_TOKEN", "high", "medium", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("STRIPE_SECRET", "high", "medium", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{12,}\b")),
    ("JWT_LITERAL", "medium", "low", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b")),
    ("SECRET_ASSIGNMENT", "medium", "low", re.compile(
        r"(?i)(?:\b(?:password|passwd|client_secret|api_key|secret_key|access_token)\b)\s*[:=]\s*['\"]([^'\"\r\n]{8,})['\"]")),
)

_CODE_RULES = (
    ("DYNAMIC_EVAL", "medium", "medium", re.compile(r"\b(?:eval|Function)\s*\("), "Dynamic JavaScript evaluation requires dataflow review"),
    ("DOM_HTML_SINK", "medium", "low", re.compile(r"\.(?:innerHTML|outerHTML)\s*=|\binsertAdjacentHTML\s*\("), "HTML injection sink; confirm untrusted source reaches it"),
    ("DOCUMENT_WRITE", "low", "low", re.compile(r"\bdocument\.write(?:ln)?\s*\("), "Document-writing sink requires dataflow review"),
    ("POSTMESSAGE_WILDCARD", "medium", "low", re.compile(r"\.postMessage\s*\([^;\n]{0,400},\s*['\"]\*['\"]\s*\)"), "Wildcard postMessage target origin; assess message sensitivity"),
    ("MESSAGE_LISTENER", "info", "low", re.compile(r"addEventListener\s*\(\s*['\"]message['\"]"), "Message handler; inspect origin validation"),
    ("STORAGE_TOKEN", "low", "low", re.compile(r"\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"](?:token|access_token|jwt|auth)['\"]", re.I), "Authentication-related browser storage; assess threat model"),
    ("SOURCE_MAP_REFERENCE", "info", "high", re.compile(r"(?m)//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)"), "Source map reference discovered"),
    ("DEBUGGER_STATEMENT", "info", "medium", re.compile(r"\bdebugger\s*;"), "Debugger statement in shipped JavaScript"),
)

_ENDPOINT = re.compile(r"(?P<q>['\"`])(?P<path>(?:https?://[^\s'\"`<>]{4,}|/(?:api|graphql|v\d+|admin|internal|auth|oauth)/[^\s'\"`<>]{0,180}))(?P=q)", re.I)


def _safe_asset_id(url: str) -> str:
    return sha256(url.encode("utf-8", "replace")).hexdigest()[:20]


def _line(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _evidence_hash(rule: str, asset_id: str, text: str) -> str:
    return sha256((rule + "\0" + asset_id + "\0" + text).encode("utf-8", "replace")).hexdigest()[:20]


def _is_placeholder(value: str) -> bool:
    value = value.strip().lower()
    if value in {"password", "secret", "changeme", "undefined", "null", "example", "placeholder", "your_api_key", "your_password"}:
        return True
    if any(x in value for x in ("${", "{{", "<your", "process.env", "import.meta.env")):
        return True
    return len(set(value)) < 4


class JSAnalyzer:
    def __init__(self, config: JSConfig | None = None):
        self.config = config or JSConfig()

    def analyze(self, assets: Iterable[JSAsset], *, scope_check: Callable[[str], bool]) -> JSReport:
        if not callable(scope_check):
            raise ValueError("scope_check callback is required")
        seen = analyzed = skipped = 0
        findings: list[JSFinding] = []
        dedupe: set[tuple[str, str, int, str]] = set()
        for asset in assets:
            if seen >= self.config.max_assets:
                break
            seen += 1
            if not isinstance(asset, JSAsset) or not isinstance(asset.url, str) or not isinstance(asset.source, str):
                skipped += 1
                continue
            try:
                parts = urlsplit(asset.url)
                in_scope = parts.scheme in {"http", "https"} and bool(parts.hostname) and bool(scope_check(asset.url))
            except Exception:
                in_scope = False
            if not in_scope:
                skipped += 1
                continue
            source = asset.source
            if len(source.encode("utf-8", "replace")) > self.config.max_asset_bytes:
                skipped += 1
                continue
            analyzed += 1
            asset_id = _safe_asset_id(asset.url)

            def add(rule: str, severity: str, confidence: str, match: re.Match, description: str, metadata: Mapping[str, str] | None = None):
                if len(findings) >= self.config.max_findings:
                    return
                lineno = _line(source, match.start())
                fingerprint = _evidence_hash(rule, asset_id, match.group(0))
                key = (rule, asset_id, match.start(), fingerprint)
                if key in dedupe:
                    return
                dedupe.add(key)
                findings.append(JSFinding(rule, severity, confidence, asset_id, lineno, description, fingerprint, dict(metadata or {})))

            for rule, severity, confidence, pattern in _SECRET_RULES:
                for match in list(pattern.finditer(source))[:self.config.max_matches_per_rule_per_asset]:
                    if rule == "SECRET_ASSIGNMENT" and _is_placeholder(match.group(1)):
                        continue
                    if not self.config.include_low_confidence and confidence == "low":
                        continue
                    add(rule, severity, confidence, match, "Potential embedded secret; verify ownership and validity without using it")
            for rule, severity, confidence, pattern, description in _CODE_RULES:
                for match in list(pattern.finditer(source))[:self.config.max_matches_per_rule_per_asset]:
                    if not self.config.include_low_confidence and confidence == "low":
                        continue
                    add(rule, severity, confidence, match, description)
            for match in list(_ENDPOINT.finditer(source))[:self.config.max_matches_per_rule_per_asset]:
                path = match.group("path")
                try:
                    target = urlsplit(path)
                    # Avoid collecting arbitrary unrelated external URLs as endpoint findings.
                    if target.scheme and target.hostname != parts.hostname:
                        continue
                except ValueError:
                    continue
                add("ENDPOINT_REFERENCE", "info", "medium", match,
                    "API or application endpoint reference discovered; assess authorization separately",
                    {"path_hash": sha256(path.split("?", 1)[0].encode()).hexdigest()[:16]})
        findings.sort(key=lambda f: (f.asset_id, f.line, f.rule_id, f.evidence_hash))
        return JSReport(seen, analyzed, skipped, tuple(findings))


# Convenient public names for use by the broader Muninn codebase.
JSAnalysisAuditor = JSAnalyzer
JavaScriptAsset = JSAsset
