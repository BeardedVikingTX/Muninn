"""Passive injection-surface inventory for Muninn HTTP captures.

No network calls, payload generation, authorization decisions, or secret values
in returned objects. Input coordinates are observational, not proof of safety.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from urllib.parse import parse_qsl, urlsplit

from core.http_models import HTTPRequest, HTTPTransaction

MAX_POINTS = 2048
MAX_BODY = 2 * 1024 * 1024
MAX_DEPTH = 24
MAX_FIELDS = 1024
SENSITIVE = re.compile(r"(?:passw(?:or)?d|secret|token|api[_-]?key|auth|session|cookie|csrf|xsrf|bearer|credential|private[_-]?key|otp|mfa|refresh)", re.I)
HEADER_CANDIDATES = frozenset({'origin', 'referer', 'user-agent', 'accept-language', 'x-forwarded-host', 'forwarded', 'x-original-url', 'x-rewrite-url', 'x-requested-with'})


class InjectionPointError(ValueError):
    """Input cannot be safely inventoried under configured limits."""


@dataclass(frozen=True, slots=True)
class InjectionPoint:
    id: str
    location: str
    name: str
    pointer: str
    occurrence: int
    value_type: str
    encoding: str
    sensitive: bool
    active_testing_allowed: bool = False

    def safe_summary(self) -> dict[str, object]:
        # Names and pointers can themselves contain secrets. Only opaque ID and
        # structural fields are suitable for routine logs.
        return {'id': self.id, 'location': self.location, 'value_type': self.value_type,
                'encoding': self.encoding, 'sensitive': self.sensitive,
                'active_testing_allowed': False}


class InjectionPointDiscovery:
    def __init__(self, *, max_points: int = MAX_POINTS, max_body: int = MAX_BODY):
        if type(max_points) is not int or not 1 <= max_points <= MAX_POINTS:
            raise ValueError('invalid max_points')
        if type(max_body) is not int or not 1 <= max_body <= MAX_BODY:
            raise ValueError('invalid max_body')
        self.max_points, self.max_body = max_points, max_body

    def discover(self, value: HTTPRequest | HTTPTransaction) -> tuple[InjectionPoint, ...]:
        request = value.request if isinstance(value, HTTPTransaction) else value
        if not isinstance(request, HTTPRequest):
            raise TypeError('expected HTTPRequest or HTTPTransaction')
        points: list[InjectionPoint] = []
        seen: dict[tuple[str, str], int] = {}

        def add(location: str, name: str, pointer: str, kind: str, encoding: str, sensitive: bool = False) -> None:
            if len(points) >= self.max_points:
                raise InjectionPointError('injection point limit exceeded')
            key = (location, pointer)
            occurrence = seen.get(key, 0)
            seen[key] = occurrence + 1
            # Digest includes only coordinates, never raw values or body content.
            coordinate = json.dumps([location, pointer, occurrence], separators=(',', ':'), ensure_ascii=True)
            identifier = 'ip-' + sha256(coordinate.encode()).hexdigest()[:24]
            points.append(InjectionPoint(identifier, location, name, pointer, occurrence,
                                         kind, encoding, sensitive or bool(SENSITIVE.search(name))))

        try:
            target = urlsplit(request.target)
        except ValueError as exc:
            raise InjectionPointError('invalid request target') from None
        if target.query:
            for name, val in _pairs(target.query):
                add('query', name, name, 'string', 'url')
        # A path segment is a candidate input surface, not necessarily mutable.
        path = target.path
        for index, segment in enumerate(path.split('/')):
            if segment and index > 0:
                add('path', str(index), f'/{index}', 'string', 'url')

        for h in request.headers:
            lname = h.name.lower()
            if lname in HEADER_CANDIDATES:
                add('header', h.name, lname, 'string', 'header')
            elif lname == 'cookie':
                for item in h.value.split(';')[:MAX_FIELDS]:
                    if '=' in item:
                        name = item.split('=', 1)[0].strip()
                        if name:
                            add('cookie', name, name, 'string', 'cookie', True)

        if len(request.body) > self.max_body:
            raise InjectionPointError('request body exceeds discovery limit')
        ctype = (request.headers.get('Content-Type') or '').split(';', 1)[0].strip().lower()
        if not request.body:
            return tuple(points)
        if ctype == 'application/x-www-form-urlencoded':
            try:
                body = request.body.decode('utf-8', 'strict')
            except UnicodeDecodeError:
                return tuple(points)
            for name, val in _pairs(body):
                add('form', name, name, 'string', 'url')
        elif ctype == 'application/json' or ctype.endswith('+json'):
            try:
                decoded = json.loads(request.body.decode('utf-8', 'strict'), parse_constant=_reject_constant)
            except (UnicodeError, ValueError, RecursionError):
                return tuple(points)
            stack = [(decoded, '', 0)]
            while stack:
                obj, pointer, depth = stack.pop()
                if depth > MAX_DEPTH:
                    raise InjectionPointError('JSON nesting limit exceeded')
                if isinstance(obj, dict):
                    if len(obj) > MAX_FIELDS:
                        raise InjectionPointError('JSON object field limit exceeded')
                    children = []
                    for key, child in obj.items():
                        ptr = pointer + '/' + key.replace('~', '~0').replace('/', '~1')
                        children.append((child, ptr, depth + 1))
                        if not isinstance(child, (dict, list)):
                            add('json', key, ptr, _json_type(child), 'json-pointer',
                                any(SENSITIVE.search(part) for part in ptr.split('/')))
                    stack.extend(reversed(children))
                elif isinstance(obj, list):
                    if len(obj) > MAX_FIELDS:
                        raise InjectionPointError('JSON array limit exceeded')
                    children = []
                    for idx, child in enumerate(obj):
                        ptr = pointer + '/' + str(idx)
                        children.append((child, ptr, depth + 1))
                        if not isinstance(child, (dict, list)):
                            add('json', str(idx), ptr, _json_type(child), 'json-pointer',
                                any(SENSITIVE.search(part) for part in ptr.split('/')))
                    stack.extend(reversed(children))
        # XML, multipart, and binary formats deliberately not interpreted yet.
        return tuple(points)


def _pairs(value: str) -> list[tuple[str, str]]:
    try:
        return parse_qsl(value, keep_blank_values=True, max_num_fields=MAX_FIELDS,
                         errors='replace')
    except ValueError:
        raise InjectionPointError('parameter count limit exceeded') from None


def _reject_constant(value: str) -> None:
    raise ValueError('nonstandard JSON number')


def _json_type(value: object) -> str:
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'boolean'
    if isinstance(value, (int, float)):
        return 'number'
    return 'string'
