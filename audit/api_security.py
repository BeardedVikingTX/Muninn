"""Muninn passive API security auditor.

Offline analysis of captured, in-scope HTTP exchanges. This module never sends
requests, mutates accounts, or assumes that heuristic observations are exploits.

Integrate by adapting your existing HTTPTransaction objects to APIExchange.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit, parse_qsl
import hashlib
import json
import re

_SECRET_KEYS = frozenset({"token", "access_token", "refresh_token", "id_token", "api_key", "apikey", "key", "password", "passwd", "secret", "authorization", "code", "client_secret", "session", "sessionid", "jwt"})
_API_PATH = re.compile(r"(?:^|/)(?:api|graphql|rest|v[1-9][0-9]*)(?:/|$)", re.I)
_TRACE = re.compile(r"(?:Traceback \(most recent call last\)|\bat [\w.$]+\([^\n)]*:\d+\)|(?:File \"[^\"]+\", line \d+)|SQL syntax.*(?:MySQL|MariaDB)|(?:psycopg2|sqlalchemy|sqlite3)\.[\w.]+(?:Error|Exception))", re.I)
_JSON_CT = re.compile(r"(?:application/(?:[\w.+-]*\+)?json|application/graphql-response\+json)", re.I)


def _headers(value: Mapping[str, Any] | None) -> dict[str, str]:
    """Normalize header names; preserve repeated values supplied as sequences."""
    result: dict[str, str] = {}
    for key, raw in (value or {}).items():
        k = str(key).lower().strip()
        if not k:
            continue
        if isinstance(raw, (list, tuple)):
            result[k] = ", ".join(str(v) for v in raw)
        else:
            result[k] = str(raw)
    return result


def _body(value: bytes | str | None, limit: int) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value[:limit].decode("utf-8", "replace")
    return value[:limit]


def _endpoint(url: str) -> str:
    """Strip query and fragment; never return embedded URL credentials."""
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme.lower()}://{host}{port}{p.path or '/'}"


@dataclass(frozen=True)
class APIExchange:
    method: str
    url: str
    request_headers: Mapping[str, Any] = field(default_factory=dict)
    response_status: int | None = None
    response_headers: Mapping[str, Any] = field(default_factory=dict)
    response_body: bytes | str | None = None
    request_body: bytes | str | None = None


@dataclass(frozen=True)
class APIObservation:
    rule_id: str
    severity: str
    confidence: str
    endpoint: str
    method: str
    status: int | None
    description: str
    remediation: str
    evidence: tuple[str, ...] = ()

    def safe_summary(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "severity": self.severity,
                "confidence": self.confidence, "endpoint": self.endpoint,
                "method": self.method, "status": self.status,
                "description": self.description, "remediation": self.remediation,
                "evidence": list(self.evidence)}


@dataclass(frozen=True)
class APIAuditReport:
    exchanges_seen: int
    api_exchanges: int
    observations: tuple[APIObservation, ...]
    truncated: bool = False

    def safe_summary(self) -> dict[str, Any]:
        return {"exchanges_seen": self.exchanges_seen,
                "api_exchanges": self.api_exchanges,
                "observation_count": len(self.observations),
                "truncated": self.truncated,
                "by_rule": {k: sum(x.rule_id == k for x in self.observations)
                            for k in sorted({x.rule_id for x in self.observations})}}

    def to_json(self) -> str:
        return json.dumps({**self.safe_summary(), "observations": [o.safe_summary() for o in self.observations]}, sort_keys=True, indent=2)


class APISecurityAuditor:
    """Deterministic passive analyzer; no network I/O or active exploitation."""

    def __init__(self, *, max_exchanges: int = 10000,
                 max_body_bytes: int = 65536,
                 max_observations: int = 2000,
                 require_scope: bool = True):
        if min(max_exchanges, max_body_bytes, max_observations) <= 0:
            raise ValueError("Limits must be positive")
        self.max_exchanges = max_exchanges
        self.max_body_bytes = max_body_bytes
        self.max_observations = max_observations
        self.require_scope = require_scope

    def analyze(self, exchanges: Iterable[APIExchange], *,
                scope_check: Any = None) -> APIAuditReport:
        """Analyze exchanges after checking scope.

        scope_check(url) must return True for authorized URLs. By default it is
        required; supply a real engagement scope checker, not an allow-all lambda.
        """
        if self.require_scope and scope_check is None:
            raise ValueError("scope_check is required to prevent out-of-scope analysis")
        observations: list[APIObservation] = []
        seen = api_count = 0
        truncated = False
        for exchange in exchanges:
            if seen >= self.max_exchanges:
                truncated = True
                break
            seen += 1
            if scope_check is not None and not scope_check(exchange.url):
                continue
            if not self._is_api(exchange):
                continue
            api_count += 1
            for finding in self._inspect(exchange):
                if len(observations) >= self.max_observations:
                    truncated = True
                    break
                observations.append(finding)
            if truncated:
                break
        return APIAuditReport(seen, api_count, tuple(observations), truncated)

    @staticmethod
    def _is_api(e: APIExchange) -> bool:
        p = urlsplit(e.url)
        h = _headers(e.response_headers)
        req = _headers(e.request_headers)
        return bool(_API_PATH.search(p.path) or _JSON_CT.search(h.get("content-type", ""))
                    or _JSON_CT.search(req.get("accept", "")))

    def _inspect(self, e: APIExchange) -> list[APIObservation]:
        req, res = _headers(e.request_headers), _headers(e.response_headers)
        p = urlsplit(e.url)
        ep = _endpoint(e.url)
        method = e.method.upper().strip()[:16]
        findings: list[APIObservation] = []

        def emit(rule: str, severity: str, confidence: str, desc: str,
                 fix: str, *evidence: str) -> None:
            findings.append(APIObservation(rule, severity, confidence, ep, method,
                                           e.response_status, desc, fix, tuple(evidence)))

        # Query names only: values are deliberately never retained.
        sensitive = sorted({key.lower() for key, _ in parse_qsl(p.query, keep_blank_values=True)
                            if key.lower() in _SECRET_KEYS})
        if sensitive:
            emit("API-QUERY-SECRET", "medium", "high",
                 "Sensitive-looking parameter names appear in the URL query.",
                 "Send credentials and recovery secrets in appropriate protected request fields; avoid URLs.",
                 "parameter_names=" + ",".join(sensitive))

        origin = res.get("access-control-allow-origin", "").strip()
        creds = res.get("access-control-allow-credentials", "").strip().lower()
        if origin == "*" and creds == "true":
            emit("API-CORS-WILDCARD-CREDENTIALS", "medium", "high",
                 "CORS advertises wildcard origin alongside credentials; browsers reject this combination.",
                 "Use explicit trusted origins with credentialed requests.",
                 "allow_origin=wildcard", "allow_credentials=true")
        elif origin == "*" and req.get("authorization"):
            emit("API-CORS-WILDCARD-AUTH", "info", "low",
                 "Authenticated API response advertises wildcard CORS origin; assess data sensitivity and browser behavior.",
                 "Restrict cross-origin access where required by the API's trust model.",
                 "allow_origin=wildcard")
        elif origin and origin != "*" and creds == "true":
            request_origin = req.get("origin", "")
            if request_origin and origin == request_origin:
                emit("API-CORS-REFLECTION-REVIEW", "info", "low",
                     "Credentialed CORS response matches the captured Origin; determine whether origin validation is strict.",
                     "Validate origins against an explicit allowlist and test with authorized controlled origins.",
                     "credentialed_origin_match=true")

        if method in {"GET", "HEAD"} and (req.get("authorization") or "cookie" in req):
            cc = res.get("cache-control", "").lower()
            if e.response_status == 200 and not any(x in cc for x in ("no-store", "private", "no-cache")):
                emit("API-AUTH-CACHE-REVIEW", "low", "medium",
                     "Authenticated GET response lacks explicit private/no-store/no-cache directives.",
                     "Review whether personalized responses can be stored in shared caches.",
                     "cache_control_protective_directive=false")

        if p.scheme.lower() == "http" and (req.get("authorization") or "cookie" in req):
            emit("API-AUTH-HTTP", "high", "high",
                 "Captured authenticated request uses plaintext HTTP.",
                 "Require HTTPS for authenticated API traffic.",
                 "scheme=http")

        if res.get("access-control-expose-headers", "").strip() == "*" and creds == "true":
            emit("API-CORS-EXPOSE-WILDCARD", "info", "medium",
                 "Credentialed response advertises wildcard exposed headers; browser interpretation differs for credentialed requests.",
                 "Specify explicit exposed header names.", "expose_headers=wildcard")

        if method == "OPTIONS" and "allow" in res:
            methods = {m.strip().upper() for m in res["allow"].split(",")}
            if "TRACE" in methods:
                emit("API-TRACE-ADVERTISED", "low", "medium",
                     "Server advertises TRACE in the Allow header.",
                     "Disable TRACE unless explicitly required and protected.", "trace_advertised=true")

        text = _body(e.response_body, self.max_body_bytes)
        if e.response_status is not None and e.response_status >= 400 and _TRACE.search(text):
            emit("API-VERBOSE-ERROR", "medium", "medium",
                 "Error response contains a stack trace or backend error signature.",
                 "Return generic client errors and log detailed diagnostics server-side.",
                 "error_signature_detected=true")

        # Avoid embedding any body text or values in evidence.
        if e.response_status == 200 and "graphql" in p.path.lower():
            if '"__schema"' in text or '"__type"' in text:
                emit("API-GRAPHQL-INTROSPECTION-REVIEW", "info", "medium",
                     "Captured GraphQL response appears to contain introspection metadata.",
                     "Review whether schema introspection is appropriate for this deployment.",
                     "introspection_response=true")

        if "set-cookie" in res and p.scheme.lower() == "https":
            # One combined header cannot reliably distinguish multiple cookies.
            cookie = res["set-cookie"].lower()
            if "secure" not in cookie:
                emit("API-COOKIE-SECURE-REVIEW", "low", "medium",
                     "Set-Cookie response appears to omit the Secure attribute.",
                     "Set Secure on authentication cookies; verify each Set-Cookie header individually.",
                     "secure_attribute_observed=false")

        return findings


def fingerprint_exchange(exchange: APIExchange) -> str:
    """Stable opaque identifier, without storing raw URLs or payloads."""
    canonical = f"{exchange.method.upper()}\n{_endpoint(exchange.url)}\n{exchange.response_status}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]


__all__ = ["APIExchange", "APIObservation", "APIAuditReport", "APISecurityAuditor", "fingerprint_exchange"]
