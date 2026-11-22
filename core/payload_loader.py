"""Offline, bounded, fail-closed YAML payload catalog for Muninn.

Definitions are DATA, never executable instructions. Loading does not authorize
active testing, interpolate variables, open URLs, or transmit requests.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import re
import stat
from typing import Iterable

import yaml

MAX_FILE_BYTES = 256 * 1024
MAX_FILES = 512
MAX_PAYLOADS = 4096
MAX_TEMPLATE = 8192
MAX_DEPTH = 16
_ID = re.compile(r'^[A-Z][A-Z0-9_-]{2,79}$')
_CATEGORY = re.compile(r'^[a-z][a-z0-9_]{1,63}$')
_CONTEXTS = frozenset({'query', 'form', 'json', 'path', 'header', 'cookie', 'xml', 'multipart', 'graphql', 'websocket'})
_ENCODINGS = frozenset({'none', 'url', 'json', 'xml', 'header', 'base64'})
_MODES = frozenset({'passive', 'authorized_active'})
_DETECTIONS = frozenset({'response_contains_marker', 'status_difference', 'header_difference', 'manual_review', 'oast_callback'})
_ALLOWED_TOP = frozenset({'schema_version', 'id', 'name', 'category', 'description', 'payload', 'contexts', 'execution', 'detection', 'safety'})


class PayloadError(ValueError):
    """Invalid, unsupported, or unsafe catalog data (no raw payload in errors)."""


class _StrictLoader(yaml.SafeLoader):
    """Safe YAML without aliases, anchors, custom tags or duplicate mappings."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise PayloadError('YAML aliases are not supported')
        event = self.peek_event()
        if getattr(event, 'anchor', None) is not None:
            raise PayloadError('YAML anchors are not supported')
        return super().compose_node(parent, index)


def _mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        if not isinstance(key_node, yaml.ScalarNode) or key_node.tag != 'tag:yaml.org,2002:str':
            raise PayloadError('mapping keys must be strings')
        key = loader.construct_object(key_node, deep=True)
        if key in result:
            raise PayloadError('duplicate YAML mapping key')
        result[key] = loader.construct_object(value_node, deep=True)
    return result


_StrictLoader.add_constructor('tag:yaml.org,2002:map', _mapping)


def _fail(message: str):
    raise PayloadError(message)


def _mapping_field(value, allowed, label):
    if type(value) is not dict or not set(value).issubset(allowed):
        _fail('invalid ' + label + ' fields')
    return value


def _string(value, label, limit=256, *, allow_empty=False):
    if type(value) is not str or len(value.encode('utf-8')) > limit or (not value and not allow_empty) or '\x00' in value:
        _fail('invalid ' + label)
    return value


def _boolean(value, label):
    if type(value) is not bool:
        _fail('invalid ' + label)
    return value


def _check_depth(value, depth=0):
    if depth > MAX_DEPTH:
        _fail('YAML nesting limit exceeded')
    if type(value) is dict:
        if len(value) > 128:
            _fail('YAML mapping too large')
        for key, child in value.items():
            _check_depth(child, depth + 1)
    elif type(value) is list:
        if len(value) > 128:
            _fail('YAML sequence too large')
        for child in value:
            _check_depth(child, depth + 1)


@dataclass(frozen=True, slots=True)
class PayloadDefinition:
    id: str
    name: str
    category: str
    description: str
    template: str
    encoding: str
    contexts: tuple[str, ...]
    mode: str
    requires_scope: bool
    requires_active_permission: bool
    max_requests: int
    detection_type: str
    confidence: str
    destructive: bool
    out_of_band: bool
    requires_manual_review: bool

    def safe_summary(self) -> dict[str, object]:
        # Do not include template or free-text fields in routine logs.
        return {'id': self.id, 'category': self.category, 'contexts': self.contexts,
                'mode': self.mode, 'destructive': self.destructive,
                'out_of_band': self.out_of_band}

    def compatible_with(self, point) -> bool:
        """Context match only; NEVER an authorization or execution decision."""
        return getattr(point, 'location', None) in self.contexts


def validate_payload(value: object) -> PayloadDefinition:
    obj = _mapping_field(value, _ALLOWED_TOP, 'payload')
    if type(obj.get('schema_version')) is not int or obj['schema_version'] != 1:
        _fail('unsupported schema_version')
    identifier = _string(obj.get('id'), 'id', 80)
    category = _string(obj.get('category'), 'category', 64)
    if not _ID.fullmatch(identifier) or not _CATEGORY.fullmatch(category):
        _fail('invalid identifier or category')
    name = _string(obj.get('name'), 'name', 160)
    description = _string(obj.get('description', ''), 'description', 1024, allow_empty=True)
    payload = _mapping_field(obj.get('payload'), {'template', 'encoding'}, 'payload.template')
    template = _string(payload.get('template'), 'template', MAX_TEMPLATE)
    encoding = _string(payload.get('encoding'), 'encoding', 32)
    if encoding not in _ENCODINGS:
        _fail('unsupported encoding')
    contexts = obj.get('contexts')
    if type(contexts) is not list or not 1 <= len(contexts) <= len(_CONTEXTS):
        _fail('invalid contexts')
    if any(type(c) is not str or c not in _CONTEXTS for c in contexts) or len(set(contexts)) != len(contexts):
        _fail('invalid or duplicate context')
    execution = _mapping_field(obj.get('execution'), {'mode', 'requires_scope', 'requires_active_permission', 'max_requests'}, 'execution')
    mode = _string(execution.get('mode'), 'mode', 32)
    if mode not in _MODES:
        _fail('unsupported execution mode')
    scope = _boolean(execution.get('requires_scope'), 'requires_scope')
    permission = _boolean(execution.get('requires_active_permission'), 'requires_active_permission')
    requests = execution.get('max_requests')
    if type(requests) is not int or not 0 <= requests <= 10:
        _fail('invalid max_requests')
    if not scope or not permission or (mode == 'passive' and requests != 0) or (mode == 'authorized_active' and requests < 1):
        _fail('execution policy must fail closed')
    detection = _mapping_field(obj.get('detection'), {'type', 'confidence'}, 'detection')
    dtype = _string(detection.get('type'), 'detection.type', 64)
    confidence = _string(detection.get('confidence'), 'confidence', 32)
    if dtype not in _DETECTIONS or confidence not in {'informational', 'low', 'medium'}:
        _fail('unsupported detection metadata')
    safety = _mapping_field(obj.get('safety'), {'destructive', 'out_of_band', 'requires_manual_review'}, 'safety')
    destructive = _boolean(safety.get('destructive'), 'destructive')
    oast = _boolean(safety.get('out_of_band'), 'out_of_band')
    review = _boolean(safety.get('requires_manual_review'), 'requires_manual_review')
    if destructive and not review:
        _fail('destructive definitions require manual review')
    if oast and dtype != 'oast_callback':
        _fail('OAST definitions require callback detection')
    return PayloadDefinition(identifier, name, category, description, template, encoding,
                             tuple(contexts), mode, scope, permission, requests, dtype,
                             confidence, destructive, oast, review)


def _read_regular_file(path: Path, max_bytes: int) -> bytes:
    # Linux/Unix no-follow open, with fstat on the opened descriptor.
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0)
    if not hasattr(os, 'O_NOFOLLOW'):
        raise PayloadError('secure file opening unavailable')
    flags |= os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise PayloadError('cannot securely open payload file') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            _fail('invalid file type or size')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read(max_bytes + 1)
        if len(raw) > max_bytes:
            _fail('payload file exceeds size limit')
        return raw
    finally:
        os.close(fd)


def _parse(raw: bytes) -> list[PayloadDefinition]:
    try:
        text = raw.decode('utf-8', 'strict')
        data = yaml.load(text, Loader=_StrictLoader)
    except (UnicodeError, yaml.YAMLError, RecursionError):
        raise PayloadError('invalid YAML document') from None
    if data is None:
        return []  # Empty placeholders are not executable definitions.
    _check_depth(data)
    if type(data) is dict:
        documents = [data]
    elif type(data) is list:
        documents = data
    else:
        _fail('expected payload mapping or list')
    if len(documents) > 128:
        _fail('too many definitions in file')
    return [validate_payload(doc) for doc in documents]


class PayloadLoader:
    """Load a trusted, local catalog. No interpolation, imports or network access."""

    def __init__(self, root: str | os.PathLike[str], *, max_files: int = MAX_FILES,
                 max_payloads: int = MAX_PAYLOADS):
        if type(max_files) is not int or not 1 <= max_files <= MAX_FILES:
            raise ValueError('invalid max_files')
        if type(max_payloads) is not int or not 1 <= max_payloads <= MAX_PAYLOADS:
            raise ValueError('invalid max_payloads')
        self.root = Path(root)
        self.max_files = max_files
        self.max_payloads = max_payloads

    def load(self) -> tuple[PayloadDefinition, ...]:
        root = self.root
        if root.is_symlink() or not root.is_dir():
            _fail('payload root must be a real directory')
        found: list[PayloadDefinition] = []
        identifiers: set[str] = set()
        count = 0
        # os.walk does not follow symlinked directories by default; reject them.
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs.sort()
            files.sort()
            for dirname in dirs:
                if (Path(directory) / dirname).is_symlink():
                    _fail('symlinked catalog directory')
            for filename in files:
                path = Path(directory) / filename
                if path.suffix.lower() not in {'.yaml', '.yml'}:
                    continue
                count += 1
                if count > self.max_files:
                    _fail('catalog file limit exceeded')
                for definition in _parse(_read_regular_file(path, MAX_FILE_BYTES)):
                    if definition.id in identifiers:
                        _fail('duplicate payload identifier')
                    identifiers.add(definition.id)
                    found.append(definition)
                    if len(found) > self.max_payloads:
                        _fail('catalog payload limit exceeded')
        return tuple(found)

    def select(self, point, *, catalog: Iterable[PayloadDefinition] | None = None) -> tuple[PayloadDefinition, ...]:
        """Compatibility filtering only. The audit engine must enforce permission."""
        definitions = self.load() if catalog is None else catalog
        return tuple(p for p in definitions if p.compatible_with(point))
