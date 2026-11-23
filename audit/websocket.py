"""Muninn WebSocket security evidence analyzer (offline, standard library).

This module does not open sockets or perform active attacks. Its findings describe
observed evidence, not independently established vulnerabilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
from typing import Any, Callable, Iterable, Mapping, Optional
from urllib.parse import urlsplit, parse_qsl
import ipaddress
import json
import re

_TOKEN = re.compile(r"(?i)(?:bearer\s+[a-z0-9._~+/-]{12,}|(?:gh[pousr]_[a-z0-9_]{15,}|xox[baprs]-[a-z0-9-]{12,}|sk_live_[a-z0-9]{12,}))")
_SECRET_KEY = re.compile(r"(?i)^(?:token|access_token|refresh_token|id_token|jwt|secret|password|passwd|api[_-]?key|authorization|session(?:_id)?)$")
_SENSITIVE_FIELD = re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key)")
_ID_FIELDS = frozenset({'user_id', 'account_id', 'tenant_id', 'owner_id', 'channel_id', 'room_id', 'document_id'})


def _digest(value: str) -> str:
    return sha256(value.encode('utf-8', errors='replace')).hexdigest()[:20]


def _headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(k).lower().strip(): str(v) for k, v in headers.items()}


def _host(value: str) -> str:
    try:
        u = urlsplit(value)
        return (u.hostname or '').lower().rstrip('.')
    except ValueError:
        return ''


def _valid_endpoint(value: str) -> bool:
    try:
        u = urlsplit(value)
        return u.scheme.lower() in ('ws', 'wss', 'http', 'https') and bool(u.hostname) and not u.username and not u.password
    except ValueError:
        return False


def _safe_path(value: str) -> str:
    try:
        u = urlsplit(value)
        return (u.path or '/')[:160]
    except ValueError:
        return '/'


def _is_private_host(host: str) -> bool:
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return host in ('localhost',) or host.endswith(('.local', '.internal'))


@dataclass(frozen=True)
class WebSocketCapture:
    url: str
    handshake_status: Optional[int] = None
    request_headers: Mapping[str, str] = field(default_factory=dict)
    response_headers: Mapping[str, str] = field(default_factory=dict)
    messages: tuple['WebSocketMessage', ...] = ()
    scenario: str = 'default'
    # Trusted fixture metadata; caller must independently validate these claims.
    cross_origin_test: bool = False
    origin_rejected: Optional[bool] = None
    cookie_authenticated: bool = False
    auth_required: Optional[bool] = None
    unauthenticated_connection_accepted: Optional[bool] = None


@dataclass(frozen=True)
class WebSocketMessage:
    direction: str  # client_to_server | server_to_client
    payload: str
    principal_id: str = ''
    resource_id: str = ''
    expected_access: Optional[bool] = None
    resource_disclosed: bool = False
    disclosure_verified: bool = False
    action_committed: bool = False
    commit_verified: bool = False
    operation: str = ''


@dataclass(frozen=True)
class WebSocketPolicy:
    allowed_origins: frozenset[str] = frozenset()
    require_tls: bool = True
    require_authentication: bool = True
    max_messages_per_capture: int = 1000
    max_message_chars: int = 100000
    max_captures: int = 10000
    max_findings: int = 3000
    inspect_json_depth: int = 12

    def __post_init__(self) -> None:
        for name in ('max_messages_per_capture', 'max_message_chars', 'max_captures', 'max_findings', 'inspect_json_depth'):
            if getattr(self, name) < 1:
                raise ValueError(f'{name} must be positive')


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    confidence: str
    endpoint: str
    evidence: str
    scenario_fingerprint: str
    message_index: Optional[int] = None


@dataclass(frozen=True)
class AuditReport:
    findings: tuple[Finding, ...]
    captures_analyzed: int
    captures_skipped: int
    messages_analyzed: int
    truncated: bool

    def to_json(self) -> str:
        return json.dumps({'findings': [asdict(f) for f in self.findings],
                           'captures_analyzed': self.captures_analyzed,
                           'captures_skipped': self.captures_skipped,
                           'messages_analyzed': self.messages_analyzed,
                           'truncated': self.truncated}, sort_keys=True, indent=2)


def _walk_json(value: Any, max_depth: int):
    stack = [(value, (), 0)]
    visited = 0
    while stack and visited < 20000:
        obj, path, depth = stack.pop()
        visited += 1
        if depth > max_depth:
            continue
        if isinstance(obj, dict):
            for key, child in obj.items():
                key = str(key)
                yield path + (key,), child
                if isinstance(child, (dict, list)):
                    stack.append((child, path + (key,), depth + 1))
        elif isinstance(obj, list):
            for child in obj[:1000]:
                if isinstance(child, (dict, list)):
                    stack.append((child, path + ('[]',), depth + 1))


class WebSocketAuditor:
    def __init__(self, policy: Optional[WebSocketPolicy] = None):
        self.policy = policy or WebSocketPolicy()

    def analyze(self, captures: Iterable[WebSocketCapture], *, scope_check: Callable[[str], bool]) -> AuditReport:
        if not callable(scope_check):
            raise TypeError('scope_check callback is required')
        findings: list[Finding] = []
        seen: set[tuple[str, str, str, Optional[int]]] = set()
        analyzed = skipped = messages = 0
        truncated = False

        def add(code: str, severity: str, confidence: str, capture: WebSocketCapture, evidence: str, index: Optional[int] = None):
            nonlocal truncated
            # No query strings, raw payloads, principal IDs, resource IDs or token values.
            endpoint = f'{_host(capture.url)}{_safe_path(capture.url)}'
            scenario_hash = _digest(capture.scenario)
            key = (code, endpoint, scenario_hash, index)
            if key in seen:
                return
            if len(findings) >= self.policy.max_findings:
                truncated = True
                return
            seen.add(key)
            findings.append(Finding(code, severity, confidence, endpoint, evidence, scenario_hash, index))

        for cap in captures:
            if analyzed + skipped >= self.policy.max_captures:
                truncated = True
                break
            if not isinstance(cap, WebSocketCapture) or not _valid_endpoint(cap.url):
                skipped += 1
                continue
            try:
                allowed = bool(scope_check(cap.url))
            except Exception:
                allowed = False
            if not allowed:
                skipped += 1
                continue
            analyzed += 1
            u = urlsplit(cap.url)
            req = _headers(cap.request_headers)
            resp = _headers(cap.response_headers)
            upgraded = cap.handshake_status == 101
            origin = req.get('origin', '')
            origin_host = _host(origin)
            target_host = _host(cap.url)
            cookie_auth = cap.cookie_authenticated or bool(req.get('cookie'))

            if self.policy.require_tls and u.scheme in ('ws', 'http'):
                add('INSECURE_TRANSPORT', 'medium', 'high', cap, 'WebSocket endpoint uses a plaintext transport scheme')
            if any(_SECRET_KEY.fullmatch(k) for k, _ in parse_qsl(u.query, keep_blank_values=True)):
                add('CREDENTIAL_IN_URL', 'medium', 'high', cap, 'Credential-named query parameter in handshake URL')
            if _TOKEN.search(u.query):
                add('TOKEN_PATTERN_IN_URL', 'medium', 'medium', cap, 'Token-like value in handshake URL')
            if upgraded and req.get('sec-websocket-key') and resp.get('sec-websocket-accept') is None:
                add('MISSING_ACCEPT_HEADER', 'low', 'medium', cap, 'Upgrade response missing Sec-WebSocket-Accept')
            if upgraded and req.get('sec-websocket-protocol') and resp.get('sec-websocket-protocol'):
                offered = {s.strip() for s in req['sec-websocket-protocol'].split(',')}
                selected = resp['sec-websocket-protocol'].strip()
                if selected not in offered:
                    add('UNOFFERED_SUBPROTOCOL', 'medium', 'high', cap, 'Server selected a subprotocol not offered by the client')
            if upgraded and self.policy.require_authentication and cap.auth_required is True and cap.unauthenticated_connection_accepted is True:
                add('UNAUTHENTICATED_UPGRADE', 'high', 'high', cap, 'Trusted fixture reports an unauthenticated connection accepted despite required authentication')
            if upgraded and origin and origin_host and target_host and origin_host != target_host and cookie_auth:
                if cap.cross_origin_test and cap.origin_rejected is False:
                    add('CROSS_ORIGIN_COOKIE_UPGRADE', 'high', 'high', cap, 'Trusted cross-origin test accepted a cookie-authenticated upgrade; verify CSWSH impact')
                elif self.policy.allowed_origins and origin not in self.policy.allowed_origins:
                    add('UNEXPECTED_ORIGIN_UPGRADE', 'medium', 'medium', cap, 'Upgrade accepted an origin outside the configured allowlist')
                else:
                    add('CROSS_ORIGIN_COOKIE_REVIEW', 'low', 'low', cap, 'Cross-origin cookie-authenticated upgrade requires origin policy review')
            if upgraded and not origin and cookie_auth:
                add('MISSING_ORIGIN_REVIEW', 'low', 'low', cap, 'Cookie-authenticated upgrade without Origin; nonbrowser clients may legitimately omit it')
            if len(cap.messages) > self.policy.max_messages_per_capture:
                truncated = True
            for idx, msg in enumerate(cap.messages[:self.policy.max_messages_per_capture]):
                if not isinstance(msg, WebSocketMessage):
                    continue
                if msg.direction not in ('client_to_server', 'server_to_client'):
                    continue
                if len(msg.payload) > self.policy.max_message_chars:
                    truncated = True
                    continue
                messages += 1
                if _TOKEN.search(msg.payload):
                    add('TOKEN_IN_MESSAGE', 'medium', 'medium', cap, 'Token-like material present in WebSocket message', idx)
                try:
                    parsed = json.loads(msg.payload)
                except (ValueError, TypeError):
                    parsed = None
                if isinstance(parsed, (dict, list)):
                    sensitive_keys = set()
                    resource_keys = set()
                    for path, value in _walk_json(parsed, self.policy.inspect_json_depth):
                        key = path[-1]
                        if _SENSITIVE_FIELD.search(key) and isinstance(value, (str, int, float, bool)):
                            sensitive_keys.add(key.lower())
                        if key.lower() in _ID_FIELDS:
                            resource_keys.add(key.lower())
                    if sensitive_keys and msg.direction == 'server_to_client':
                        add('SENSITIVE_FIELD_IN_SERVER_MESSAGE', 'medium', 'medium', cap, 'Sensitive-named fields in server message; inspect access controls', idx)
                    if resource_keys and msg.direction == 'client_to_server':
                        add('OBJECT_REFERENCE_IN_CLIENT_MESSAGE', 'info', 'high', cap, 'Client controls an object identifier; review message-level authorization', idx)
                if msg.expected_access is False:
                    if msg.direction == 'server_to_client' and msg.resource_disclosed:
                        if msg.disclosure_verified:
                            add('VERIFIED_UNAUTHORIZED_DISCLOSURE', 'high', 'high', cap, 'Trusted fixture confirms protected resource disclosure to unauthorized principal', idx)
                        else:
                            add('POSSIBLE_UNAUTHORIZED_DISCLOSURE', 'medium', 'low', cap, 'Caller reports resource disclosure without independent verification', idx)
                    if msg.direction == 'client_to_server' and msg.action_committed:
                        if msg.commit_verified:
                            add('VERIFIED_UNAUTHORIZED_ACTION', 'high', 'high', cap, 'Trusted fixture confirms unauthorized state-changing operation committed', idx)
                        else:
                            add('POSSIBLE_UNAUTHORIZED_ACTION', 'medium', 'low', cap, 'Caller reports committed operation without independent verification', idx)
        return AuditReport(tuple(findings), analyzed, skipped, messages, truncated)


__all__ = ['WebSocketAuditor', 'WebSocketCapture', 'WebSocketMessage', 'WebSocketPolicy', 'Finding', 'AuditReport']
