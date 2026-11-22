"""Muninn's offline HTTP data model (Python >= 3.10; standard library only).

This module DOES NOT send requests, parse Burp XML, determine authorization,
redact arbitrary secrets, or claim that a response demonstrates a vulnerability.
Raw messages are sensitive: never log, repr, or JSON-serialize them by default.
HTTP/2 and HTTP/3 captures need an adapter that supplies semantic fields; their
binary wire formats cannot be decoded by the HTTP/1.x parser below.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from typing import Iterable, Iterator
from urllib.parse import parse_qsl, urlsplit
import re

MAX_MESSAGE_BYTES = 32 * 1024 * 1024
MAX_START_LINE_BYTES = 16 * 1024
MAX_HEADER_BYTES = 256 * 1024
MAX_HEADERS = 1024
_TOKEN = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_HTTP_VERSION = re.compile(r"^HTTP/(?:1\.[01]|2(?:\.0)?|3(?:\.0)?)$")
_METHOD = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class HTTPModelError(ValueError):
    """Invalid or unsupported HTTP representation."""


class MessageKind(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"


@dataclass(frozen=True, slots=True)
class Header:
    """A single ordered HTTP header; duplicate names are preserved.

    Values use Latin-1 round-tripping for HTTP/1 raw bytes. No trimming is
    performed beyond the optional whitespace immediately after the colon.
    """
    name: str
    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _TOKEN.fullmatch(self.name.encode('ascii', errors='ignore')) or not self.name.isascii():
            raise HTTPModelError("invalid header name")
        if not isinstance(self.value, str) or any(c in self.value for c in '\r\n\x00'):
            raise HTTPModelError("header value contains forbidden characters")
        try:
            self.value.encode('latin-1')
        except UnicodeEncodeError as exc:
            raise HTTPModelError("header value must be Latin-1 representable") from exc


@dataclass(frozen=True, slots=True)
class Headers:
    """Immutable ordered header collection with case-insensitive lookups."""
    entries: tuple[Header, ...] = field(default_factory=tuple, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.entries, tuple) or any(not isinstance(h, Header) for h in self.entries):
            raise TypeError("entries must be tuple[Header, ...]")
        if len(self.entries) > MAX_HEADERS:
            raise HTTPModelError("too many headers")

    def get_all(self, name: str) -> tuple[str, ...]:
        if not isinstance(name, str):
            raise TypeError("name must be str")
        return tuple(h.value for h in self.entries if h.name.casefold() == name.casefold())

    def get(self, name: str, default: str | None = None) -> str | None:
        values = self.get_all(name)
        return values[0] if values else default

    def __iter__(self) -> Iterator[Header]:
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)


@dataclass(frozen=True, slots=True)
class QueryParameter:
    name: str
    value: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class HTTPRequest:
    method: str
    target: str = field(repr=False)
    version: str = 'HTTP/1.1'
    headers: Headers = field(default_factory=Headers, repr=False)
    body: bytes = field(default=b'', repr=False)
    raw: bytes | None = field(default=None, repr=False)
    # Source-provided absolute URL is optional (e.g. Burp <url> field).
    source_url: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.method, str) or not _METHOD.fullmatch(self.method) or not self.method.isascii():
            raise HTTPModelError("invalid HTTP method")
        _check_common(self.version, self.headers, self.body, self.raw)
        if not isinstance(self.target, str) or not self.target or '\r' in self.target or '\n' in self.target:
            raise HTTPModelError("invalid request target")
        if self.source_url is not None:
            _check_url(self.source_url)

    @property
    def query_parameters(self) -> tuple[QueryParameter, ...]:
        # Keep blanks, duplicates and order. Never assume plus signs are literal.
        query = urlsplit(self.target).query if self.target != '*' else ''
        return tuple(QueryParameter(k, v) for k, v in parse_qsl(query, keep_blank_values=True, max_num_fields=4096))

    @property
    def content_sha256(self) -> str:
        return sha256(self.raw if self.raw is not None else self.body).hexdigest()

    def safe_summary(self) -> dict[str, object]:
        """Metadata only. Excludes target, URL, header values and body."""
        return {"method": self.method, "version": self.version,
                "header_count": len(self.headers), "body_bytes": len(self.body),
                "has_raw": self.raw is not None}


@dataclass(frozen=True, slots=True)
class HTTPResponse:
    status_code: int
    reason: str = field(default='', repr=False)
    version: str = 'HTTP/1.1'
    headers: Headers = field(default_factory=Headers, repr=False)
    body: bytes = field(default=b'', repr=False)
    raw: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.status_code) is not int or not 100 <= self.status_code <= 999:
            raise HTTPModelError("invalid status code")
        if not isinstance(self.reason, str) or '\r' in self.reason or '\n' in self.reason:
            raise HTTPModelError("invalid reason phrase")
        _check_common(self.version, self.headers, self.body, self.raw)

    @property
    def content_sha256(self) -> str:
        return sha256(self.raw if self.raw is not None else self.body).hexdigest()

    def safe_summary(self) -> dict[str, object]:
        return {"status_code": self.status_code, "version": self.version,
                "header_count": len(self.headers), "body_bytes": len(self.body),
                "has_raw": self.raw is not None}


@dataclass(frozen=True, slots=True)
class HTTPTransaction:
    """One captured request and optional response, linked to an opaque source ID."""
    source_id: str
    request: HTTPRequest = field(repr=False)
    response: HTTPResponse | None = field(default=None, repr=False)
    timestamp: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', self.source_id):
            raise HTTPModelError("source_id must be a safe opaque identifier")
        if not isinstance(self.request, HTTPRequest):
            raise TypeError("request must be HTTPRequest")
        if self.response is not None and not isinstance(self.response, HTTPResponse):
            raise TypeError("response must be HTTPResponse or None")
        if self.timestamp is not None and (not isinstance(self.timestamp, str) or len(self.timestamp) > 80):
            raise HTTPModelError("invalid timestamp")

    def safe_summary(self) -> dict[str, object]:
        return {"source_id": self.source_id, "request": self.request.safe_summary(),
                "response": self.response.safe_summary() if self.response else None,
                "timestamp": self.timestamp}


def _check_url(value: str) -> None:
    if not isinstance(value, str) or len(value) > 16384 or any(ord(c) < 32 for c in value):
        raise HTTPModelError("invalid source URL")
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in ('http', 'https') or not parts.hostname or parts.username is not None or parts.password is not None:
            raise HTTPModelError("source URL must be HTTP(S), absolute, and contain no userinfo")
        _ = parts.port
    except ValueError as exc:
        raise HTTPModelError("invalid source URL") from exc


def _check_common(version: str, headers: Headers, body: bytes, raw: bytes | None) -> None:
    if not isinstance(version, str) or not _HTTP_VERSION.fullmatch(version):
        raise HTTPModelError("unsupported HTTP version")
    if not isinstance(headers, Headers):
        raise TypeError("headers must be Headers")
    if not isinstance(body, bytes) or len(body) > MAX_MESSAGE_BYTES:
        raise HTTPModelError("invalid or oversized body")
    if raw is not None and (not isinstance(raw, bytes) or len(raw) > MAX_MESSAGE_BYTES):
        raise HTTPModelError("invalid or oversized raw message")


def _split_http1(raw: bytes) -> tuple[bytes, Headers, bytes]:
    if not isinstance(raw, bytes) or len(raw) > MAX_MESSAGE_BYTES:
        raise HTTPModelError("raw HTTP message must be bounded bytes")
    # Accept CRLF or LF-only exports, but never mix delimiters silently.
    if b'\r\n\r\n' in raw:
        sep, line_sep = b'\r\n\r\n', b'\r\n'
    elif b'\n\n' in raw and b'\r' not in raw.split(b'\n\n', 1)[0]:
        sep, line_sep = b'\n\n', b'\n'
    else:
        raise HTTPModelError("missing HTTP header/body separator")
    head, body = raw.split(sep, 1)
    if len(head) > MAX_HEADER_BYTES:
        raise HTTPModelError("header block too large")
    lines = head.split(line_sep)
    if not lines or not lines[0] or len(lines[0]) > MAX_START_LINE_BYTES:
        raise HTTPModelError("invalid start line")
    entries: list[Header] = []
    for line in lines[1:]:
        if not line or line[:1] in (b' ', b'\t'):
            raise HTTPModelError("empty or folded header line is unsupported")
        name, colon, value = line.partition(b':')
        if not colon or not _TOKEN.fullmatch(name):
            raise HTTPModelError("malformed header")
        entries.append(Header(name.decode('ascii'), value.lstrip(b' \t').decode('latin-1')))
        if len(entries) > MAX_HEADERS:
            raise HTTPModelError("too many headers")
    return lines[0], Headers(tuple(entries)), body


def parse_http1_request(raw: bytes, *, source_url: str | None = None) -> HTTPRequest:
    """Parse a captured HTTP/1.x message without replaying or rewriting it.

    Content-Encoding, chunked transfer encoding and multipart bodies are left
    untouched. Callers must not treat this as a wire-protocol security validator.
    """
    start, headers, body = _split_http1(raw)
    try:
        method, target, version = start.decode('latin-1').split(' ', 2)
    except ValueError as exc:
        raise HTTPModelError("malformed request line") from exc
    if version not in ('HTTP/1.0', 'HTTP/1.1'):
        raise HTTPModelError("not an HTTP/1.x request")
    return HTTPRequest(method, target, version, headers, body, raw, source_url)


def parse_http1_response(raw: bytes) -> HTTPResponse:
    start, headers, body = _split_http1(raw)
    try:
        version, status, *reason = start.decode('latin-1').split(' ', 2)
        status_code = int(status)
    except (ValueError, TypeError) as exc:
        raise HTTPModelError("malformed response line") from exc
    if version not in ('HTTP/1.0', 'HTTP/1.1') or not re.fullmatch(r'[0-9]{3}', status):
        raise HTTPModelError("not a valid HTTP/1.x response line")
    return HTTPResponse(status_code, reason[0] if reason else '', version, headers, body, raw)
