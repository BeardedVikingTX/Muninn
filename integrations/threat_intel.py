"""Muninn threat intelligence: offline-first, advisory-only indicator correlation.

No DNS, network, target scanning, or automatic enforcement. External adapters are
explicitly injected and must use the approved API transport. Intelligence is
untrusted; matches are NOT proof of compromise or a vulnerability.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable
from urllib.parse import urlsplit

MAX_RECORDS = 10000
MAX_RESULTS = 100
MAX_AGE_SECONDS = 365 * 86400
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_HEX = re.compile(r"[0-9a-f]+\Z")
_SOURCE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")


class ThreatIntelError(ValueError):
    """Invalid intelligence data; exception text never includes supplied values."""


def normalize_indicator(kind: str, value: str) -> str:
    if kind not in {'domain', 'ip', 'url', 'sha256'} or not isinstance(value, str) or len(value) > 2048:
        raise ThreatIntelError('Invalid indicator')
    if any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ThreatIntelError('Invalid indicator')
    if kind == 'sha256':
        normalized = value.lower()
        if len(normalized) != 64 or not _HEX.fullmatch(normalized):
            raise ThreatIntelError('Invalid SHA-256')
        return normalized
    if kind == 'ip':
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise ThreatIntelError('Invalid IP') from None
        if not ip.is_global:
            raise ThreatIntelError('Non-public IP')
        return ip.compressed
    if kind == 'domain':
        try:
            domain = value.rstrip('.').encode('idna').decode('ascii').lower()
        except UnicodeError:
            raise ThreatIntelError('Invalid domain') from None
        if len(domain) > 253 or '.' not in domain or not all(_LABEL.fullmatch(p) for p in domain.split('.')):
            raise ThreatIntelError('Invalid domain')
        # Avoid leaking internal, unqualified or special-use names into enrichment.
        if domain.endswith(('.local', '.localhost', '.internal', '.test', '.invalid', '.example')):
            raise ThreatIntelError('Non-public domain')
        return domain
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError()
        if parsed.port not in (None, 443):
            raise ValueError()
        host = parsed.hostname
        try:
            host = normalize_indicator('ip', host)
            host = f'[{host}]' if ':' in host else host
        except ThreatIntelError:
            host = normalize_indicator('domain', host)
        path = parsed.path or '/'
        if len(path) > 1024 or len(parsed.query) > 512:
            raise ValueError()
        return 'https://' + host + path + ('?' + parsed.query if parsed.query else '')
    except (ValueError, UnicodeError):
        raise ThreatIntelError('Invalid HTTPS URL') from None


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ThreatIntelError('Invalid timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise ThreatIntelError('Invalid timestamp') from None
    if parsed.tzinfo is None:
        raise ThreatIntelError('Timestamp must include timezone')
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class Indicator:
    kind: str
    value: str

    def __post_init__(self):
        object.__setattr__(self, 'value', normalize_indicator(self.kind, self.value))


@dataclass(frozen=True, slots=True)
class ThreatRecord:
    indicator: Indicator
    source: str
    observed_at: str
    expires_at: str
    category: str
    reference: str = ''

    def __post_init__(self):
        if not isinstance(self.indicator, Indicator) or not isinstance(self.source, str) or not _SOURCE.fullmatch(self.source):
            raise ThreatIntelError('Invalid source')
        if self.category not in {'malware', 'phishing', 'botnet', 'spam', 'scanner', 'suspicious', 'unknown'}:
            raise ThreatIntelError('Invalid category')
        start, end = _timestamp(self.observed_at), _timestamp(self.expires_at)
        if end <= start or (end - start).total_seconds() > MAX_AGE_SECONDS:
            raise ThreatIntelError('Invalid validity window')
        if not isinstance(self.reference, str) or len(self.reference) > 512 or (self.reference and not self.reference.startswith('https://')):
            raise ThreatIntelError('Invalid reference')
        if any(ord(c) < 33 for c in self.reference):
            raise ThreatIntelError('Invalid reference')


@dataclass(frozen=True, slots=True)
class ThreatMatch:
    indicator: Indicator
    records: tuple[ThreatRecord, ...]
    status: str
    advisory_only: bool = True
    confirmed_compromise: bool = False


@dataclass(frozen=True, slots=True)
class EnrichmentResult:
    status: str
    match: ThreatMatch | None = None


@dataclass(frozen=True, slots=True)
class ThreatAdapter:
    name: str
    supports: frozenset[str]
    lookup: Callable[[Indicator], Iterable[ThreatRecord]]

    def __post_init__(self):
        if not isinstance(self.name, str) or not _SOURCE.fullmatch(self.name):
            raise ThreatIntelError('Invalid adapter')
        if not isinstance(self.supports, frozenset) or not self.supports or not self.supports <= {'domain', 'ip', 'url', 'sha256'}:
            raise ThreatIntelError('Invalid adapter capabilities')
        if not callable(self.lookup):
            raise ThreatIntelError('Invalid adapter callable')


class ThreatIntel:
    """Thread-safe bounded in-memory store; no implicit external calls.

    Records are supplied by the caller. Explicit adapters can enrich indicators,
    but the caller must separately authorize both network access and disclosure.
    """
    def __init__(self, *, adapters: Iterable[ThreatAdapter] = (), online: bool = False,
                 max_records: int = MAX_RECORDS, clock: Callable[[], datetime] | None = None):
        if type(online) is not bool or type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS:
            raise ThreatIntelError('Invalid configuration')
        self.online = online
        self.max_records = max_records
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._records: dict[Indicator, dict[tuple[str, str, str], ThreatRecord]] = {}
        self._count = 0
        self._adapters: dict[str, ThreatAdapter] = {}
        for adapter in adapters:
            if not isinstance(adapter, ThreatAdapter) or adapter.name in self._adapters:
                raise ThreatIntelError('Duplicate or invalid adapter')
            self._adapters[adapter.name] = adapter

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ThreatIntelError('Invalid clock')
        return now.astimezone(timezone.utc)

    def ingest(self, records: Iterable[ThreatRecord]) -> int:
        # Materialize with a hard bound; reject atomically on malformed batches.
        batch = []
        for item in records:
            if len(batch) >= self.max_records or not isinstance(item, ThreatRecord):
                raise ThreatIntelError('Invalid or oversized batch')
            batch.append(item)
        with self._lock:
            now = self._now()
            staged = {k: dict(v) for k, v in self._records.items()}
            for record in batch:
                if _timestamp(record.expires_at) <= now:
                    continue
                bucket = staged.setdefault(record.indicator, {})
                bucket[(record.source, record.category, record.reference)] = record
            total = sum(len(b) for b in staged.values())
            if total > self.max_records:
                raise ThreatIntelError('Store capacity exceeded')
            self._records = staged
            self._count = total
        return len(batch)

    def lookup(self, indicator: Indicator) -> ThreatMatch:
        if not isinstance(indicator, Indicator):
            raise ThreatIntelError('Invalid indicator')
        with self._lock:
            now = self._now()
            bucket = self._records.get(indicator, {})
            fresh = tuple(sorted((r for r in bucket.values() if _timestamp(r.observed_at) <= now < _timestamp(r.expires_at)),
                                 key=lambda r: (r.source, r.category, r.reference)))
        return ThreatMatch(indicator, fresh[:MAX_RESULTS], 'matched' if fresh else 'no_current_match')

    def enrich(self, indicator: Indicator, provider: str, *, approved: bool = False,
               permission: bool = False) -> EnrichmentResult:
        if not isinstance(indicator, Indicator) or not isinstance(provider, str):
            return EnrichmentResult('invalid_request')
        adapter = self._adapters.get(provider)
        if adapter is None:
            return EnrichmentResult('provider_not_registered')
        if indicator.kind not in adapter.supports:
            return EnrichmentResult('unsupported_indicator')
        if not self.online:
            return EnrichmentResult('offline')
        if approved is not True or permission is not True:
            return EnrichmentResult('approval_required')
        try:
            records = adapter.lookup(indicator)
            batch = []
            for record in records:
                if len(batch) >= MAX_RESULTS or not isinstance(record, ThreatRecord):
                    return EnrichmentResult('invalid_provider_data')
                if record.indicator != indicator or record.source != provider:
                    return EnrichmentResult('provider_mismatch')
                batch.append(record)
            self.ingest(batch)
        except Exception:
            return EnrichmentResult('provider_error')
        return EnrichmentResult('ok', self.lookup(indicator))

    def status(self) -> dict[str, object]:
        with self._lock:
            return {'records': self._count, 'indicators': len(self._records),
                    'providers': tuple(sorted(self._adapters)), 'online': self.online}

    def fingerprint(self, indicator: Indicator) -> str:
        if not isinstance(indicator, Indicator):
            raise ThreatIntelError('Invalid indicator')
        return hashlib.sha256((indicator.kind + '\0' + indicator.value).encode('utf-8')).hexdigest()
