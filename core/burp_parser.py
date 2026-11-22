"""Offline, streaming Burp Suite XML history importer.

Requires defusedxml. Never sends requests or prints captured secrets. Burp's
ordinary internal DTD is supported; entity declarations and external references
are forbidden. Invalid items fail closed by default; optional skip mode returns
only successfully parsed transactions and exposes bounded error statistics.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

from defusedxml.ElementTree import iterparse
from defusedxml.common import DefusedXmlException

from core.http_models import (
    HTTPModelError, HTTPTransaction, MAX_MESSAGE_BYTES,
    parse_http1_request, parse_http1_response, HTTPRequest, HTTPResponse, _split_http1,
)

MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_ITEMS = 100_000
MAX_ITEM_TEXT = 96 * 1024 * 1024


class BurpParseError(ValueError):
    """Burp history is invalid, unsafe, or unsupported."""


@dataclass(frozen=True, slots=True)
class ParseIssue:
    index: int
    reason: str


class BurpParser:
    def __init__(self, *, skip_invalid: bool = False, max_items: int = MAX_ITEMS,
                 max_file_bytes: int = MAX_FILE_BYTES):
        if type(skip_invalid) is not bool or not 1 <= max_items <= MAX_ITEMS or not 1 <= max_file_bytes <= MAX_FILE_BYTES:
            raise ValueError('invalid parser limits')
        self.skip_invalid = skip_invalid
        self.max_items = max_items
        self.max_file_bytes = max_file_bytes
        self.issues: list[ParseIssue] = []
        self.processed = 0

    def parse(self, path: str | Path) -> Iterator[HTTPTransaction]:
        """Yield transactions in capture order; iterate fully to finish parsing.

        XML and HTTP messages are not persisted or replayed. Never log an
        exception from a lower-level XML parser: it may contain input data.
        """
        import os
        import stat
        self.issues = []
        self.processed = 0
        flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
        try:
            fd = os.open(os.fspath(path), flags)
            mode = os.fstat(fd)
            if not stat.S_ISREG(mode.st_mode) or mode.st_size > self.max_file_bytes:
                raise BurpParseError('input must be a bounded regular file')
        except OSError as exc:
            raise BurpParseError('unable to open history file safely') from exc
        try:
            with os.fdopen(fd, 'rb') as stream:
                fd = -1
                reader = _BoundedReader(stream, self.max_file_bytes)
                try:
                    events = iterparse(reader, events=('start', 'end'),
                                       forbid_dtd=False, forbid_entities=True,
                                       forbid_external=True)
                    root = None
                    for event, elem in events:
                        if root is None:
                            if event != 'start' or elem.tag != 'items':
                                raise BurpParseError('expected Burp items root')
                            root = elem
                        elif event == 'end' and elem.tag == 'item':
                            self.processed += 1
                            if self.processed > self.max_items:
                                raise BurpParseError('item count limit exceeded')
                            try:
                                tx = _parse_item(elem, self.processed)
                            except (BurpParseError, HTTPModelError, ValueError, TypeError) as exc:
                                if not self.skip_invalid:
                                    raise BurpParseError(f'invalid item {self.processed}: unsupported or malformed capture') from None
                                if len(self.issues) < 1000:
                                    self.issues.append(ParseIssue(self.processed, 'unsupported or malformed capture'))
                            else:
                                yield tx
                            finally:
                                elem.clear()
                                root.clear()
                        elif event == 'end' and elem.tag not in ('items', 'item'):
                            # Keep child content until the parent item is parsed.
                            pass
                    if root is None:
                        raise BurpParseError('empty XML document')
                except (DefusedXmlException, __import__('xml.etree.ElementTree', fromlist=['ParseError']).ParseError) as exc:
                    raise BurpParseError('unsafe or malformed XML') from None
                except (OSError, UnicodeError, OverflowError) as exc:
                    raise BurpParseError('unable to read history XML') from None
        finally:
            if fd >= 0:
                os.close(fd)


class _BoundedReader:
    def __init__(self, stream, limit: int):
        self.stream = stream
        self.remaining = limit

    def read(self, n: int = -1) -> bytes:
        if self.remaining <= 0:
            # One extra byte distinguishes exactly-at-limit from oversized.
            if self.stream.read(1):
                raise BurpParseError('file size limit exceeded')
            return b''
        n = min(65536 if n < 0 else n, self.remaining)
        data = self.stream.read(n)
        self.remaining -= len(data)
        return data


def _field(item, name: str, *, required: bool = True) -> str | None:
    nodes = item.findall(name)
    if len(nodes) != 1:
        if not required and not nodes:
            return None
        raise BurpParseError('missing or duplicate XML field')
    node = nodes[0]
    if len(node):
        raise BurpParseError('nested XML field')
    text = node.text or ''
    if len(text) > MAX_ITEM_TEXT:
        raise BurpParseError('oversized XML field')
    return text


def _decode(item, name: str, *, required: bool) -> bytes | None:
    nodes = item.findall(name)
    if not nodes and not required:
        return None
    if len(nodes) != 1 or len(nodes[0]):
        raise BurpParseError('invalid message field')
    node = nodes[0]
    encoded = node.attrib.get('base64', 'false')
    if encoded not in ('true', 'false'):
        raise BurpParseError('invalid base64 flag')
    value = node.text or ''
    if len(value) > MAX_ITEM_TEXT:
        raise BurpParseError('oversized message field')
    if not value and not required:
        return None
    if encoded == 'true':
        compact = ''.join(value.split())
        if len(compact) > ((MAX_MESSAGE_BYTES + 2) // 3) * 4 + 4:
            raise BurpParseError('encoded message too large')
        try:
            raw = base64.b64decode(compact, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise BurpParseError('invalid base64 message') from None
    else:
        try:
            raw = value.encode('latin-1')
        except UnicodeEncodeError:
            raise BurpParseError('non-Latin-1 plain message') from None
    if len(raw) > MAX_MESSAGE_BYTES:
        raise BurpParseError('message too large')
    return raw


def _parse_item(item, index: int) -> HTTPTransaction:
    if item.tag != 'item':
        raise BurpParseError('unexpected element')
    url = _field(item, 'url')
    host = _field(item, 'host')
    protocol = _field(item, 'protocol')
    port = _field(item, 'port')
    method = _field(item, 'method')
    timestamp = _field(item, 'time', required=False)
    if not url or not host or not protocol or not port or not method:
        raise BurpParseError('missing required metadata')
    parts = urlsplit(url)
    if (parts.scheme not in ('http', 'https') or parts.scheme != protocol.lower()
            or not parts.hostname or parts.hostname.lower() != host.lower()
            or parts.username is not None or parts.password is not None
            or not port.isascii() or not port.isdecimal()
            or not 1 <= int(port) <= 65535
            or (parts.port or (443 if parts.scheme == 'https' else 80)) != int(port)):
        raise BurpParseError('inconsistent URL metadata')
    raw_req = _decode(item, 'request', required=True)
    if not raw_req:
        raise BurpParseError('empty request')
    request = _parse_request(raw_req, url)
    if request.method != method:
        raise BurpParseError('method mismatch')
    raw_resp = _decode(item, 'response', required=False)
    response = _parse_response(raw_resp) if raw_resp else None
    return HTTPTransaction(f'burp-{index:08d}', request, response, timestamp or None)


def parse_burp_history(path: str | Path, *, skip_invalid: bool = False) -> list[HTTPTransaction]:
    """Convenience for small captures; prefer BurpParser.parse for large files."""
    return list(BurpParser(skip_invalid=skip_invalid).parse(path))


def _parse_request(raw: bytes, url: str) -> HTTPRequest:
    """Burp's HTTP/2 textual export is semantic, not binary HTTP/2 wire data."""
    start, headers, body = _split_http1(raw)
    fields = start.decode('latin-1').split(' ', 2)
    if len(fields) != 3:
        raise BurpParseError('invalid request start line')
    method, target, version = fields
    if version in ('HTTP/1.0', 'HTTP/1.1'):
        return parse_http1_request(raw, source_url=url)
    if version not in ('HTTP/2', 'HTTP/2.0', 'HTTP/3', 'HTTP/3.0'):
        raise BurpParseError('unsupported request protocol')
    return HTTPRequest(method, target, version, headers, body, raw, url)


def _parse_response(raw: bytes) -> HTTPResponse:
    start, headers, body = _split_http1(raw)
    fields = start.decode('latin-1').split(' ', 2)
    if len(fields) < 2 or len(fields[1]) != 3 or not fields[1].isascii() or not fields[1].isdecimal():
        raise BurpParseError('invalid response start line')
    version, status = fields[:2]
    if version in ('HTTP/1.0', 'HTTP/1.1'):
        return parse_http1_response(raw)
    if version not in ('HTTP/2', 'HTTP/2.0', 'HTTP/3', 'HTTP/3.0'):
        raise BurpParseError('unsupported response protocol')
    return HTTPResponse(int(status), fields[2] if len(fields) == 3 else '', version, headers, body, raw)
