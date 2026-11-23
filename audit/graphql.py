"""Muninn GraphQL passive security auditor.

Analyzes authorized, previously captured GraphQL HTTP exchanges. Does not
send traffic, introspect live endpoints, or execute mutations.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
from typing import Callable, Iterable, Mapping, Optional
from urllib.parse import urlsplit
import json
import re

_INTROSPECTION = re.compile(r'\b__(?:schema|type)\b')
_DEPTH_TOKEN = re.compile(r'\.\.\.|[_A-Za-z][_0-9A-Za-z]*|[{}()]|#[^\n]*|"(?:\\.|[^"\\])*"', re.S)
_SECRET_KEYS = {'authorization', 'cookie', 'set-cookie', 'x-api-key'}

@dataclass(frozen=True)
class GraphQLCapture:
    method: str
    url: str
    status: int
    request_headers: Mapping[str, str] = field(default_factory=dict)
    response_headers: Mapping[str, str] = field(default_factory=dict)
    request_body: str = ''
    response_body: str = ''
    authenticated: bool = False
    expected_private: bool = False

@dataclass(frozen=True)
class GraphQLFinding:
    code: str
    severity: str
    endpoint_id: str
    explanation: str
    evidence: Mapping[str, object] = field(default_factory=dict)

@dataclass
class GraphQLReport:
    analyzed: int = 0
    skipped: int = 0
    findings: list[GraphQLFinding] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps({'analyzed': self.analyzed, 'skipped': self.skipped,
                           'findings': [asdict(f) for f in self.findings]},
                          sort_keys=True, separators=(',', ':'))


def _headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _endpoint_id(url: str) -> str:
    parsed = urlsplit(url)
    return sha256(f'{parsed.scheme.lower()}://{(parsed.hostname or "").lower()}:{parsed.port or (443 if parsed.scheme == "https" else 80)}{parsed.path}'.encode()).hexdigest()[:16]


def _parse_json(text: str, limit: int) -> object | None:
    if len(text.encode('utf-8')) > limit:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _queries(body: str, content_type: str, limit: int) -> list[str]:
    if len(body.encode('utf-8')) > limit:
        return []
    parsed = _parse_json(body, limit)
    if isinstance(parsed, dict):
        return [parsed['query']] if isinstance(parsed.get('query'), str) else []
    if isinstance(parsed, list):
        return [x['query'] for x in parsed if isinstance(x, dict) and isinstance(x.get('query'), str)][:25]
    if 'application/graphql' in content_type.lower():
        return [body]
    return []


def _depth(query: str) -> int:
    """Conservative selection nesting heuristic, not a GraphQL parser.

    Ignores comments, quoted strings, and braces in those strings.
    """
    current = maximum = 0
    for token in _DEPTH_TOKEN.findall(query):
        if token.startswith('#') or token.startswith('"'):
            continue
        if token == '{':
            current += 1
            maximum = max(maximum, current)
        elif token == '}':
            current = max(0, current - 1)
    return maximum


class GraphQLAuditor:
    def __init__(self, *, max_captures: int = 10000, max_body_bytes: int = 65536,
                 max_findings: int = 1000, depth_threshold: int = 12):
        if min(max_captures, max_body_bytes, max_findings, depth_threshold) < 1:
            raise ValueError('limits must be positive')
        self.max_captures = max_captures
        self.max_body_bytes = max_body_bytes
        self.max_findings = max_findings
        self.depth_threshold = depth_threshold

    def analyze(self, captures: Iterable[GraphQLCapture], *,
                scope_check: Callable[[str], bool]) -> GraphQLReport:
        if not callable(scope_check):
            raise TypeError('scope_check must be callable')
        report = GraphQLReport()
        seen: set[tuple[str, str]] = set()
        for index, capture in enumerate(captures):
            if index >= self.max_captures:
                break
            try:
                parts = urlsplit(capture.url)
                in_scope = parts.scheme in ('http', 'https') and bool(parts.hostname) and bool(scope_check(capture.url))
            except Exception:
                in_scope = False
            if not in_scope:
                report.skipped += 1
                continue
            req_h = _headers(capture.request_headers)
            resp_h = _headers(capture.response_headers)
            queries = _queries(capture.request_body, req_h.get('content-type', ''), self.max_body_bytes)
            endpoint = parts.path.lower()
            looks_graphql = bool(queries) or 'graphql' in endpoint or 'application/graphql' in req_h.get('content-type', '').lower() or 'application/graphql-response+json' in resp_h.get('content-type', '').lower()
            if not looks_graphql:
                report.skipped += 1
                continue
            report.analyzed += 1
            eid = _endpoint_id(capture.url)

            def emit(code: str, severity: str, explanation: str, **evidence: object) -> None:
                key = (eid, code)
                if key not in seen and len(report.findings) < self.max_findings:
                    seen.add(key)
                    report.findings.append(GraphQLFinding(code, severity, eid, explanation, evidence))

            if capture.method.upper() == 'GET' and any(re.search(r'\bmutation\b', q, re.I) for q in queries):
                emit('MUTATION_OVER_GET', 'medium', 'Captured GraphQL mutation was submitted using GET; review caching and CSRF controls.')
            if any(_depth(q) > self.depth_threshold for q in queries):
                emit('DEEP_QUERY_OBSERVED', 'info', 'A deeply nested GraphQL selection was captured; verify configured complexity limits.', threshold=self.depth_threshold)
            if len(queries) > 1:
                emit('BATCHED_OPERATIONS_OBSERVED', 'info', 'Multiple GraphQL operations were submitted in one HTTP request.', count=min(len(queries), 25))
            if any(_INTROSPECTION.search(q) for q in queries):
                parsed = _parse_json(capture.response_body, self.max_body_bytes)
                data = parsed.get('data') if isinstance(parsed, dict) else None
                if capture.status == 200 and isinstance(data, dict) and any(k in data for k in ('__schema', '__type')):
                    emit('INTROSPECTION_RESPONSE', 'info', 'Captured response includes GraphQL schema introspection data; check exposure policy.')
            if capture.authenticated or capture.expected_private:
                cc = resp_h.get('cache-control', '').lower()
                if capture.status == 200 and ('public' in cc or 's-maxage' in cc) and not any(x in cc for x in ('no-store', 'private')):
                    emit('POTENTIALLY_SHARED_CACHE', 'medium', 'Potentially sensitive GraphQL response advertises shared caching; review cache key and policy.')
            parsed = _parse_json(capture.response_body, self.max_body_bytes)
            if isinstance(parsed, dict) and isinstance(parsed.get('errors'), list):
                for error in parsed['errors'][:20]:
                    if not isinstance(error, dict):
                        continue
                    extensions = error.get('extensions')
                    if isinstance(extensions, dict) and any(k.lower() in ('stacktrace', 'exception', 'stack') for k in extensions):
                        emit('ERROR_INTERNALS_EXPOSED', 'medium', 'GraphQL errors include internal exception or stack metadata.')
                        break
            if capture.method.upper() == 'GET' and capture.expected_private and capture.status == 200:
                emit('PRIVATE_DATA_OVER_GET', 'info', 'Private GraphQL operation uses GET; review URL logging and caching exposure.')
        return report


__all__ = ['GraphQLCapture', 'GraphQLFinding', 'GraphQLReport', 'GraphQLAuditor']
