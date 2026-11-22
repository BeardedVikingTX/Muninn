"""Muninn passive reconnaissance intelligence router (Python 3.10+).

Offline-first: does not perform DNS resolution, HTTP requests, port scans, or
active target probing. External enrichment requires explicit per-call approval,
a registered adapter, and an independently supplied authorization decision.
The scope engine's local classification is NEVER proof of permission.

Adapters are trusted code. They must use Muninn's APIClient (or an equivalent
reviewed transport) for destination allowlisting, credentials and quotas.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z", re.ASCII)
_PROVIDER = re.compile(r"[a-z][a-z0-9_]{0,63}\Z", re.ASCII)
_ALLOWED_KINDS = frozenset({'domain', 'ip', 'url'})
_MAX_BATCH = 128
_MAX_ITEMS = 64
_MAX_VALUE = 512


class ReconError(ValueError):
    """Rejected input; never contains raw untrusted values."""


def normalize_asset(kind: str, value: str) -> str:
    """Normalize public asset identifiers without network resolution."""
    if kind not in _ALLOWED_KINDS or not isinstance(value, str) or len(value) > _MAX_VALUE:
        raise ReconError('Invalid asset kind or size')
    if not value.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ReconError('Invalid asset characters')
    if kind == 'ip':
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ReconError('Invalid IP address') from exc
        if not address.is_global:
            raise ReconError('Only globally routable IP addresses are accepted')
        return address.compressed
    if kind == 'domain':
        name = value.lower().removesuffix('.')
        if len(name) > 253 or not _NAME.fullmatch(name) or name.rsplit('.', 1)[-1].isdigit():
            raise ReconError('Invalid DNS name')
        return name
    try:
        url = urlsplit(value)
        if (url.scheme != 'https' or not url.netloc or url.username is not None
                or url.password is not None or url.fragment or url.query or url.path not in ('', '/')
                or url.port not in (None, 443)):
            raise ReconError('Only bare HTTPS origins are accepted')
        host = normalize_asset('domain', url.hostname or '')
        if url.netloc.lower() not in (host, host + ':443'):
            raise ReconError('Ambiguous URL authority')
    except ValueError as exc:
        raise ReconError('Invalid HTTPS origin') from exc
    return f'https://{host}'


@dataclass(frozen=True, slots=True)
class Asset:
    kind: str
    value: str

    def __post_init__(self):
        object.__setattr__(self, 'value', normalize_asset(self.kind, self.value))


@dataclass(frozen=True, slots=True)
class ReconFact:
    """Source-attributed observation, not an assertion of target vulnerability."""
    category: str
    value: str
    source: str

    def __post_init__(self):
        if (not isinstance(self.category, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,39}', self.category)
                or not isinstance(self.value, str) or not 1 <= len(self.value) <= 512
                or not isinstance(self.source, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', self.source)
                or any(ord(c) < 32 or ord(c) == 127 for c in self.value)):
            raise ReconError('Invalid reconnaissance fact')


@dataclass(frozen=True, slots=True)
class ReconResult:
    asset: Asset
    provider: str
    status: str
    facts: tuple[ReconFact, ...] = ()
    reason: str = ''
    # Never represents confirmed vulnerability or active-testing permission.
    vulnerability_confirmed: bool = False


@dataclass(frozen=True, slots=True)
class ProviderAdapter:
    """Trusted callable: (Asset) -> iterable[ReconFact]. No direct target traffic.

    Implementations must enforce approved API destinations and quota policy.
    `supports` declares the only asset categories that may be submitted.
    """
    name: str
    supports: frozenset[str]
    lookup: Callable[[Asset], Any] = field(repr=False, compare=False)

    def __post_init__(self):
        if (not isinstance(self.name, str) or not _PROVIDER.fullmatch(self.name)
                or not isinstance(self.supports, frozenset) or not self.supports
                or not self.supports <= _ALLOWED_KINDS or not callable(self.lookup)):
            raise ReconError('Invalid provider adapter')


class ReconRouter:
    """Offline asset inventory and explicitly approved passive enrichment.

    `permission` is an independently obtained Boolean indicating that sharing
    this asset with this external provider is allowed by the engagement rules.
    The router cannot independently verify that authorization.
    """

    def __init__(self, *, adapters=(), online: bool = False, max_facts: int = _MAX_ITEMS):
        if type(online) is not bool or type(max_facts) is not int or not 1 <= max_facts <= _MAX_ITEMS:
            raise ReconError('Invalid router configuration')
        registry = {}
        for adapter in adapters:
            if not isinstance(adapter, ProviderAdapter) or adapter.name in registry:
                raise ReconError('Duplicate or invalid provider adapter')
            registry[adapter.name] = adapter
        self.adapters: Mapping[str, ProviderAdapter] = MappingProxyType(registry)
        self.online = online
        self.max_facts = max_facts

    def inventory(self, assets) -> tuple[Asset, ...]:
        """Deduplicate an explicitly supplied asset list; never discover assets."""
        if not isinstance(assets, (list, tuple)) or len(assets) > _MAX_BATCH:
            raise ReconError('Invalid asset inventory')
        seen = set()
        output = []
        for asset in assets:
            if not isinstance(asset, Asset):
                raise ReconError('Inventory requires Asset objects')
            marker = (asset.kind, asset.value)
            if marker not in seen:
                output.append(asset)
                seen.add(marker)
        return tuple(output)

    def enrich(self, asset: Asset, provider: str, *, approved: bool = False,
               permission: bool = False) -> ReconResult:
        if not isinstance(asset, Asset) or not isinstance(provider, str):
            raise ReconError('Invalid enrichment request')
        if provider not in self.adapters:
            return ReconResult(asset, provider, 'provider_unavailable')
        adapter = self.adapters[provider]
        if asset.kind not in adapter.supports:
            return ReconResult(asset, provider, 'unsupported_asset')
        if not self.online:
            return ReconResult(asset, provider, 'offline')
        if approved is not True or permission is not True:
            return ReconResult(asset, provider, 'approval_required')
        try:
            response = adapter.lookup(asset)
            if not isinstance(response, (tuple, list)) or len(response) > self.max_facts:
                return ReconResult(asset, provider, 'invalid_provider_data')
            facts = tuple(response)
            if any(not isinstance(fact, ReconFact) or fact.source != provider for fact in facts):
                return ReconResult(asset, provider, 'invalid_provider_data')
            return ReconResult(asset, provider, 'ok', facts)
        except Exception:
            # Do not leak URLs, credentials, payloads or exception messages.
            return ReconResult(asset, provider, 'provider_error')

    def status(self) -> dict[str, Any]:
        return {
            'online': self.online,
            'registered_providers': sorted(self.adapters),
            'max_facts': self.max_facts,
            'active_scanning': False,
        }
