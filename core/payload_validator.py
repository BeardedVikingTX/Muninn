"""Offline catalog linting for Muninn payload definitions.

This module does not render templates, execute payloads, or grant permission.
It builds on the canonical schema checks in core.payload_loader.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Iterable

from core.payload_loader import PayloadDefinition, PayloadError, PayloadLoader, validate_payload

_ALLOWED_VARIABLES = frozenset({'nonce', 'oast_url', 'oast_token'})
_VARIABLE = re.compile(r'\{\{\s*([a-z][a-z0-9_]*)\s*\}\}')
_TOKEN = re.compile(r'\{\{.*?\}\}', re.DOTALL)
_CATEGORY_DIRS = frozenset({
    'account_recovery', 'api_security', 'auth_bypass', 'broken_access_control',
    'business_logic', 'cache_poisoning', 'cors', 'dependency_vulnerabilities',
    'file_upload', 'graphql', 'idor', 'js_analysis', 'jwt_security',
    'mass_assignment', 'oauth_oidc', 'open_redirect', 'path_traversal',
    'prototype_pollution', 'race_conditions', 'rce', 'sensitive_data_exposure',
    'smuggling', 'sqli', 'ssrf', 'ssti', 'websocket', 'xss', 'xxe',
})


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    severity: str
    identifier: str
    message: str


@dataclass(frozen=True, slots=True)
class ValidationReport:
    definitions: int
    diagnostics: tuple[Diagnostic, ...]

    @property
    def valid(self) -> bool:
        return not any(item.severity == 'error' for item in self.diagnostics)

    def safe_summary(self) -> dict[str, object]:
        return {'valid': self.valid, 'definitions': self.definitions,
                'errors': sum(x.severity == 'error' for x in self.diagnostics),
                'warnings': sum(x.severity == 'warning' for x in self.diagnostics)}


def _diagnostic(code: str, identifier: str, message: str, severity: str = 'error') -> Diagnostic:
    return Diagnostic(code, severity, identifier, message)


def lint_definition(definition: PayloadDefinition) -> tuple[Diagnostic, ...]:
    """Check semantic consistency after canonical schema validation."""
    if not isinstance(definition, PayloadDefinition):
        raise TypeError('expected PayloadDefinition')
    problems: list[Diagnostic] = []
    add = lambda code, message, severity='error': problems.append(_diagnostic(code, definition.id, message, severity))
    template = definition.template
    placeholders = list(_VARIABLE.finditer(template))
    remainder = _VARIABLE.sub('', template)
    if '{{' in remainder or '}}' in remainder or '{%' in template or '%}' in template:
        add('INVALID_TEMPLATE_SYNTAX', 'unrecognized template delimiter')
    for match in placeholders:
        if match.group(1) not in _ALLOWED_VARIABLES:
            add('UNKNOWN_VARIABLE', 'unsupported template variable')
    variables = {m.group(1) for m in placeholders}
    if definition.out_of_band:
        if 'oast_url' not in variables and 'oast_token' not in variables:
            add('OAST_MARKER_MISSING', 'OAST definition must reference an OAST variable')
        if definition.mode != 'authorized_active':
            add('OAST_REQUIRES_ACTIVE_MODE', 'OAST callback tests must be active')
    elif variables.intersection({'oast_url', 'oast_token'}):
        add('UNDECLARED_OAST', 'OAST variable requires out_of_band=true')
    if definition.detection_type == 'oast_callback' and not definition.out_of_band:
        add('DETECTION_MISMATCH', 'callback detection requires out_of_band=true')
    if definition.mode == 'passive' and definition.destructive:
        add('PASSIVE_DESTRUCTIVE', 'passive definition cannot be destructive')
    if definition.mode == 'passive' and definition.detection_type in {'response_contains_marker', 'oast_callback'}:
        add('PASSIVE_DETECTION_MISMATCH', 'passive definition cannot require an injected marker')
    if definition.destructive and definition.max_requests > 1:
        add('DESTRUCTIVE_REQUEST_BUDGET', 'destructive definition must limit requests to one')
    if definition.detection_type == 'response_contains_marker' and 'nonce' not in variables:
        add('MISSING_NONCE', 'marker detection should use a unique nonce', 'warning')
    if definition.encoding == 'header' and 'header' not in definition.contexts:
        add('ENCODING_CONTEXT_MISMATCH', 'header encoding requires header context')
    if definition.encoding == 'xml' and 'xml' not in definition.contexts:
        add('ENCODING_CONTEXT_MISMATCH', 'XML encoding requires XML context')
    return tuple(problems)


def validate_catalog(definitions: Iterable[PayloadDefinition], *, max_definitions: int = 4096) -> ValidationReport:
    """Validate already-loaded definitions, including cross-definition uniqueness."""
    if type(max_definitions) is not int or not 1 <= max_definitions <= 4096:
        raise ValueError('invalid max_definitions')
    seen: set[str] = set()
    problems: list[Diagnostic] = []
    count = 0
    for definition in definitions:
        count += 1
        if count > max_definitions:
            raise PayloadError('catalog definition limit exceeded')
        if not isinstance(definition, PayloadDefinition):
            raise TypeError('expected PayloadDefinition')
        # Revalidate dataclass instances too: callers may construct them directly.
        validate_payload({
            'schema_version': 1, 'id': definition.id, 'name': definition.name,
            'category': definition.category, 'description': definition.description,
            'payload': {'template': definition.template, 'encoding': definition.encoding},
            'contexts': list(definition.contexts),
            'execution': {'mode': definition.mode, 'requires_scope': definition.requires_scope,
                          'requires_active_permission': definition.requires_active_permission,
                          'max_requests': definition.max_requests},
            'detection': {'type': definition.detection_type, 'confidence': definition.confidence},
            'safety': {'destructive': definition.destructive, 'out_of_band': definition.out_of_band,
                       'requires_manual_review': definition.requires_manual_review},
        })
        if definition.id in seen:
            problems.append(_diagnostic('DUPLICATE_ID', definition.id, 'duplicate definition identifier'))
        seen.add(definition.id)
        problems.extend(lint_definition(definition))
    return ValidationReport(count, tuple(problems))


class PayloadValidator:
    """Validate the same trusted local catalog consumed by PayloadLoader."""

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def validate(self) -> ValidationReport:
        # The loader owns secure file opening, strict YAML, and schema validation.
        # Parse errors fail closed and are never echoed with source values.
        catalog = PayloadLoader(self.root).load()
        return validate_catalog(catalog)
