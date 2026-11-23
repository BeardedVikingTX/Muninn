"""Muninn passive prototype-pollution evidence auditor.

No network access, JavaScript execution, payload submission, or mutation.
Only caller-supplied observations are evaluated. Python >=3.10.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
import json
import re
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import parse_qsl, unquote, urlsplit

DANGEROUS = frozenset({'__proto__', 'prototype', 'constructor'})
SINKS = {
    'object.assign': re.compile(r'\bObject\s*\.\s*assign\s*\('),
    'lodash.merge': re.compile(r'\b(?:_|lodash)\s*\.\s*(?:merge|defaultsDeep)\s*\('),
    'deep-merge': re.compile(r'\b(?:deepmerge|deepMerge|mergeDeep)\s*\('),
    'dynamic-property-write': re.compile(r'\b[A-Za-z_$][\w$]*\s*\[\s*[A-Za-z_$][\w$]*\s*\]\s*='),
}


def fingerprint(value: str) -> str:
    return sha256(value.encode('utf-8', errors='replace')).hexdigest()[:20]


def decode_layers(value: str, limit: int = 3) -> str:
    for _ in range(limit):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def split_property_path(key: str) -> tuple[str, ...]:
    """Recognize dot/bracket property syntax without interpreting arbitrary JS."""
    key = decode_layers(key)
    key = re.sub(r'\[\s*[\'\"]([^\'\"]+)[\'\"]\s*\]', r'[\1]', key)
    return tuple(x.strip() for x in re.split(r'[.\[\]]+', key) if x.strip())


def classify_path(parts: tuple[str, ...]) -> str | None:
    """Only risky *chains* are pollution candidates, not arbitrary field names."""
    for i, part in enumerate(parts):
        if part == '__proto__' and i + 1 < len(parts):
            return 'proto-chain'
        if part == 'constructor' and i + 2 < len(parts) and parts[i + 1] == 'prototype':
            return 'constructor-prototype-chain'
    return None


def walk_json(value: Any, *, max_nodes: int, max_depth: int) -> list[tuple[tuple[str, ...], str]]:
    findings: list[tuple[tuple[str, ...], str]] = []
    stack: list[tuple[Any, tuple[str, ...], int]] = [(value, (), 0)]
    visited = 0
    while stack:
        node, path, depth = stack.pop()
        visited += 1
        if visited > max_nodes:
            raise ValueError('JSON node limit exceeded')
        if depth > max_depth:
            raise ValueError('JSON nesting limit exceeded')
        if isinstance(node, dict):
            for key, child in node.items():
                if not isinstance(key, str):
                    continue
                child_path = path + split_property_path(key)
                category = classify_path(child_path)
                if category:
                    findings.append((child_path, category))
                stack.append((child, child_path, depth + 1))
        elif isinstance(node, list):
            for child in node:
                stack.append((child, path, depth + 1))
    return findings


@dataclass(frozen=True)
class PollutionCapture:
    url: str
    method: str = 'GET'
    request_json: Any = None
    request_body: str = ''
    content_type: str = ''
    javascript_source: str = ''
    # Trusted external verification using a disposable fixture and a harmless marker.
    pollution_verified: bool = False
    verification_detail: str = ''
    scenario: str = ''


@dataclass(frozen=True)
class PollutionConfig:
    max_captures: int = 10000
    max_body_bytes: int = 2_000_000
    max_nodes: int = 20000
    max_depth: int = 64
    max_findings: int = 5000
    max_query_pairs: int = 500
    max_source_bytes: int = 2_000_000

    def __post_init__(self) -> None:
        if any(not isinstance(x, int) or isinstance(x, bool) or x < 1 for x in asdict(self).values()):
            raise ValueError('all limits must be positive integers')


@dataclass(frozen=True)
class PollutionFinding:
    category: str
    confidence: str
    severity: str
    url_fingerprint: str
    evidence_fingerprint: str
    description: str
    scenario: str = ''


@dataclass(frozen=True)
class PollutionReport:
    captures_analyzed: int
    captures_skipped: int
    findings: tuple[PollutionFinding, ...]

    def to_json(self) -> str:
        return json.dumps({
            'captures_analyzed': self.captures_analyzed,
            'captures_skipped': self.captures_skipped,
            'findings': [asdict(f) for f in self.findings],
        }, sort_keys=True, separators=(',', ':'))


class PrototypePollutionAuditor:
    def __init__(self, config: PollutionConfig | None = None):
        self.config = config or PollutionConfig()

    def analyze(self, captures: Iterable[PollutionCapture], *,
                scope_check: Callable[[str], bool]) -> PollutionReport:
        if not callable(scope_check):
            raise TypeError('scope_check must be callable')
        findings: list[PollutionFinding] = []
        seen: set[tuple[str, str, str]] = set()
        analyzed = skipped = 0
        for index, cap in enumerate(captures):
            if index >= self.config.max_captures:
                break
            if not isinstance(cap, PollutionCapture):
                skipped += 1
                continue
            # Fail closed if the scope callback fails.
            try:
                in_scope = scope_check(cap.url) is True
            except Exception:
                in_scope = False
            if not in_scope:
                skipped += 1
                continue
            analyzed += 1
            target = urlsplit(cap.url)
            url_id = fingerprint(f'{target.scheme}://{target.netloc}{target.path}')
            observations: list[tuple[str, str, str]] = []
            try:
                query = target.query
                if len(query.encode('utf-8')) <= self.config.max_body_bytes:
                    pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=self.config.max_query_pairs)
                    for key, _ in pairs:
                        kind = classify_path(split_property_path(key))
                        if kind:
                            observations.append(('untrusted-property-path', kind, key))
            except (ValueError, UnicodeError):
                pass
            body = cap.request_body
            if len(body.encode('utf-8', errors='replace')) <= self.config.max_body_bytes:
                if 'application/x-www-form-urlencoded' in cap.content_type.lower():
                    try:
                        for key, _ in parse_qsl(body, keep_blank_values=True, max_num_fields=self.config.max_query_pairs):
                            kind = classify_path(split_property_path(key))
                            if kind:
                                observations.append(('untrusted-property-path', kind, key))
                    except ValueError:
                        pass
                elif 'json' in cap.content_type.lower() and cap.request_json is None:
                    try:
                        obj = json.loads(body)
                        for path, kind in walk_json(obj, max_nodes=self.config.max_nodes, max_depth=self.config.max_depth):
                            observations.append(('untrusted-property-path', kind, '.'.join(path)))
                    except (ValueError, RecursionError):
                        pass
            if cap.request_json is not None:
                try:
                    for path, kind in walk_json(cap.request_json, max_nodes=self.config.max_nodes, max_depth=self.config.max_depth):
                        observations.append(('untrusted-property-path', kind, '.'.join(path)))
                except (ValueError, RecursionError):
                    pass
            source = cap.javascript_source
            if len(source.encode('utf-8', errors='replace')) <= self.config.max_source_bytes:
                for label, pattern in SINKS.items():
                    if pattern.search(source):
                        observations.append(('potential-merge-sink', label, label))
            for category, subtype, evidence in observations:
                if len(findings) >= self.config.max_findings:
                    break
                verified = cap.pollution_verified and category == 'untrusted-property-path'
                confidence = 'high' if verified else 'low'
                severity = 'high' if verified else 'informational'
                evid_id = fingerprint(f'{subtype}:{evidence}')
                key = (url_id, category, evid_id)
                if key in seen:
                    continue
                seen.add(key)
                description = (
                    'Trusted fixture reports a prototype change associated with an untrusted property path; '
                    'review independent verification and authorization.' if verified else
                    'Potentially dangerous property path observed; no prototype modification is established.'
                    if category == 'untrusted-property-path' else
                    'Potential object merge or dynamic property write observed; data flow and exploitability are unverified.'
                )
                findings.append(PollutionFinding(category, confidence, severity, url_id,
                                                 evid_id, description, cap.scenario[:80]))
        return PollutionReport(analyzed, skipped, tuple(findings))


__all__ = ['PollutionCapture', 'PollutionConfig', 'PollutionFinding',
           'PollutionReport', 'PrototypePollutionAuditor', 'split_property_path',
           'classify_path', 'walk_json']
