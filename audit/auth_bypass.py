"""Muninn offline authentication-boundary differential auditor.

Analyzes pre-captured, authorized HTTP exchanges. Never sends requests, modifies
credentials, or treats status codes alone as proof of an authentication bypass.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict
from hashlib import sha256
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit
import json
import re

_AUTH_STATES = frozenset({'anonymous', 'invalid', 'expired', 'authenticated', 'privileged'})
_SENSITIVE = re.compile(r'(token|secret|password|key|session|cookie|credential|authorization)', re.I)
_HTML = re.compile(r'<[^>]*>')
_DYNAMIC = re.compile(r'\b[0-9a-f]{8}-[0-9a-f-]{20,}\b|\b\d{10,}\b', re.I)


@dataclass(frozen=True)
class AuthExchange:
    method: str
    url: str
    auth_state: str
    status: int
    response_headers: Mapping[str, str] = field(default_factory=dict)
    response_body: bytes | str = b''
    request_id: str = ''
    scenario: str = 'default'
    expected_protected: bool = True

    def __post_init__(self) -> None:
        if self.auth_state not in _AUTH_STATES:
            raise ValueError('unsupported auth_state')
        if not 100 <= self.status <= 599:
            raise ValueError('invalid HTTP status')
        if not self.method or not self.url:
            raise ValueError('method and url required')
        parsed = urlsplit(self.url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise ValueError('absolute HTTP(S) URL required')


@dataclass(frozen=True)
class AuthObservation:
    rule: str
    severity: str
    confidence: str
    endpoint: str
    scenario: str
    rationale: str
    evidence: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            'rule': self.rule, 'severity': self.severity,
            'confidence': self.confidence, 'endpoint': self.endpoint,
            'scenario': self.scenario, 'rationale': self.rationale,
            'evidence': list(self.evidence),
        }


@dataclass(frozen=True)
class AuthReport:
    inspected: int
    excluded: int
    observations: tuple[AuthObservation, ...]
    truncated: bool = False

    def to_json(self) -> str:
        return json.dumps({
            'inspected': self.inspected, 'excluded': self.excluded,
            'truncated': self.truncated,
            'observations': [o.as_dict() for o in self.observations],
        }, sort_keys=True, indent=2)


class AuthBypassAuditor:
    """Conservative, bounded, passive analysis of authentication boundaries.

    The caller must supply a scope_check callback. Matching compares method,
    scheme, host, path, and scenario; query strings are excluded to avoid secrets.
    """

    def __init__(self, *, max_exchanges: int = 10000,
                 max_body_bytes: int = 65536, max_observations: int = 1000,
                 min_similarity: float = 0.90) -> None:
        if min(max_exchanges, max_body_bytes, max_observations) <= 0:
            raise ValueError('limits must be positive')
        if not 0 <= min_similarity <= 1:
            raise ValueError('min_similarity must be in [0, 1]')
        self.max_exchanges = max_exchanges
        self.max_body_bytes = max_body_bytes
        self.max_observations = max_observations
        self.min_similarity = min_similarity

    @staticmethod
    def _endpoint(exchange: AuthExchange) -> str:
        parsed = urlsplit(exchange.url)
        host = parsed.hostname.lower() if parsed.hostname else ''
        port = f':{parsed.port}' if parsed.port else ''
        return f'{parsed.scheme.lower()}://{host}{port}{parsed.path or "/"}'

    @staticmethod
    def _headers(exchange: AuthExchange) -> dict[str, str]:
        return {str(k).lower(): str(v) for k, v in exchange.response_headers.items()}

    def _body(self, exchange: AuthExchange) -> str:
        raw = exchange.response_body
        if isinstance(raw, bytes):
            raw = raw[:self.max_body_bytes].decode('utf-8', 'replace')
        else:
            raw = raw[:self.max_body_bytes]
        content_type = self._headers(exchange).get('content-type', '')
        if 'json' in content_type:
            try:
                obj = json.loads(raw)
                return self._json_shape(obj)
            except (ValueError, TypeError):
                pass
        text = _HTML.sub(' ', raw)
        text = _DYNAMIC.sub('<dynamic>', text)
        text = re.sub(r'\s+', ' ', text).strip().lower()
        # Never persist response text; hash only a normalized shape.
        return sha256(text.encode('utf-8')).hexdigest()

    def _json_shape(self, obj: object, depth: int = 0) -> str:
        if depth >= 12:
            return 'depth-limit'
        if isinstance(obj, dict):
            return '{' + ','.join(
                f'{k}:{self._json_shape(v, depth + 1)}'
                for k, v in sorted(obj.items()) if not _SENSITIVE.search(str(k))
            ) + '}'
        if isinstance(obj, list):
            return '[' + ','.join(self._json_shape(v, depth + 1) for v in obj[:20]) + ']'
        return type(obj).__name__

    def analyze(self, exchanges: Iterable[AuthExchange], *,
                scope_check: Callable[[str], bool]) -> AuthReport:
        if not callable(scope_check):
            raise TypeError('scope_check callback required')
        grouped: dict[tuple[str, str, str], list[AuthExchange]] = defaultdict(list)
        inspected = excluded = 0
        truncated = False
        for i, exchange in enumerate(exchanges):
            if i >= self.max_exchanges:
                truncated = True
                break
            if not isinstance(exchange, AuthExchange):
                raise TypeError('exchanges must contain AuthExchange instances')
            endpoint = self._endpoint(exchange)
            if not scope_check(endpoint):
                excluded += 1
                continue
            inspected += 1
            if exchange.expected_protected:
                grouped[(exchange.method.upper(), endpoint, exchange.scenario)].append(exchange)
        observations: list[AuthObservation] = []
        for (method, endpoint, scenario), group in sorted(grouped.items()):
            controls = [e for e in group if e.auth_state in ('authenticated', 'privileged')]
            unauth = [e for e in group if e.auth_state in ('anonymous', 'invalid', 'expired')]
            if not controls or not unauth:
                continue  # No baseline = no bypass claim.
            for candidate in unauth:
                if len(observations) >= self.max_observations:
                    truncated = True
                    break
                # Same status and JSON response *shape* are only review indicators.
                matches = [c for c in controls if c.status == candidate.status
                           and 200 <= c.status < 300]
                if not matches:
                    continue
                shape = self._body(candidate)
                if any(shape == self._body(c) for c in matches):
                    observations.append(AuthObservation(
                        rule='AUTH_BOUNDARY_RESPONSE_EQUIVALENCE',
                        severity='medium', confidence='low', endpoint=endpoint,
                        scenario=scenario,
                        rationale=(f'{candidate.auth_state} and authenticated captures '
                                   'returned matching successful status and response shape; '
                                   'verify resource access and identity binding manually.'),
                        evidence=(f'method={method}', f'status={candidate.status}',
                                  f'candidate_state={candidate.auth_state}',
                                  'comparison=matching_status_and_shape'),
                    ))
            if len(observations) >= self.max_observations:
                break
        return AuthReport(inspected, excluded, tuple(observations), truncated)
