"""Offline credential registry. Secret masking is not memory isolation.

Linux/POSIX Python 3.10+. No network, shell expansion, or implicit env mutation.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from types import MappingProxyType
from collections.abc import Mapping


class CredentialError(ValueError):
    """Configuration error; messages never include credential values."""


_NAMES = '''GROQ OPENROUTER MISTRAL COHERE CEREBRAS DEEPSEEK GEMINI
CYBER_ATLAS HACKER_TARGET BEVIGIL RECONEER VIRUS_TOTAL CENSYS SHODAN
OPEN_SOURCE NVD ALIEN_VAULT ABUSE_IP_DB GREY_NOISE ABUSE_CH IP_INFO
IBM_QUANTUM_PLATFORM'''.split()
DEFAULT_PROVIDERS = MappingProxyType({
    **{name.lower(): (name + '_API_KEY',) for name in _NAMES},
    'project_discovery': ('PROJECT_DISCOVERY_API_KEY', 'PROJECT_DISCOVERY_TEAM_ID'),
})
METADATA = frozenset({'GEMINI_API_NAME', 'GEMINI_PROJECT_NAME', 'GEMINI_PROJECT_NUMBER'})
_NAME = re.compile(r'[A-Z][A-Z0-9_]{0,127}\Z')
_PROVIDER = re.compile(r'[a-z][a-z0-9_]{0,127}\Z')
MAX_FILE = 128 * 1024
MAX_VALUE = 8192


def _value(value: str) -> str | None:
    if not isinstance(value, str) or len(value) > MAX_VALUE:
        raise CredentialError('Invalid credential value type or size')
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise CredentialError('Control character in credential value')
    value = value.strip()
    if (not value or (value.startswith('<') and value.endswith('>'))
            or value.casefold() in {'changeme', 'your_api_key', 'placeholder', 'none', 'null', 'api_key_here'}):
        return None
    return value


def _read_private(path: Path) -> str:
    if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'geteuid'):
        raise CredentialError('Secure file loading requires POSIX; use environment variables instead')
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise CredentialError('Credential file must be a regular file owned by the current user')
        if info.st_mode & 0o077 or info.st_nlink != 1:
            raise CredentialError('Credential file must be private and have exactly one hard link')
        if info.st_size > MAX_FILE:
            raise CredentialError('Credential file exceeds size limit')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            data = stream.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise CredentialError('Credential file exceeds size limit')
        return data.decode('utf-8-sig')
    except (OSError, UnicodeError):
        raise CredentialError('Cannot securely read credential file') from None
    finally:
        if fd is not None:
            os.close(fd)


class Credentials:
    """Read-only public interface; explicit reveal() is required for secrets.

    A configured provider is NOT proof of valid authentication or free access.
    Provider requirements are local configuration conventions, not verified API contracts.
    """
    __slots__ = ('__values', '__providers', '__sources')

    def __init__(self, values, providers, sources):
        self.__values = MappingProxyType(dict(values))
        self.__providers = MappingProxyType(dict(providers))
        self.__sources = MappingProxyType(dict(sources))

    @classmethod
    def load(cls, path: str | Path | None = None, *,
             environ: Mapping[str, str] | None = None,
             extra_providers: Mapping[str, tuple[str, ...]] | None = None) -> Credentials:
        providers = dict(DEFAULT_PROVIDERS)
        for name, fields in (extra_providers or {}).items():
            if (not isinstance(name, str) or not _PROVIDER.fullmatch(name)
                    or name in providers or not isinstance(fields, tuple) or not fields
                    or any(not isinstance(f, str) or not _NAME.fullmatch(f) for f in fields)
                    or len(set(fields)) != len(fields)):
                raise CredentialError('Invalid or duplicate provider registration')
            providers[name] = fields
        allowed = METADATA | {f for fields in providers.values() for f in fields}
        values, sources, seen = {}, {}, set()
        if path is not None:
            for number, line in enumerate(_read_private(Path(path)).split('\n'), 1):
                line = line.removesuffix('\r').strip(' ')
                if not line or line.startswith('#'):
                    continue
                name, sep, raw = line.partition('=')
                name = name.strip(' ')
                if not sep or name not in allowed or name in seen:
                    raise CredentialError(f'Invalid, unknown, or duplicate credential field at line {number}')
                seen.add(name)
                value = _value(raw)
                if value is not None:
                    values[name], sources[name] = value, 'file'
        env = os.environ if environ is None else environ
        for name in allowed:
            if name in env:
                value = _value(env[name])
                if value is None:
                    values.pop(name, None)
                    sources.pop(name, None)
                else:
                    values[name], sources[name] = value, 'environment'
        return cls(values, providers, sources)

    def configured(self, provider: str) -> bool:
        return not self.missing(provider)

    def missing(self, provider: str) -> tuple[str, ...]:
        if provider not in self.__providers:
            raise CredentialError('Unknown provider')
        return tuple(f for f in self.__providers[provider] if f not in self.__values)

    def reveal(self, field: str) -> str:
        """Return one raw value. Caller must prevent logging or unintended transmission."""
        if field not in self.__values:
            raise CredentialError('Credential field unavailable')
        return self.__values[field]

    def status(self) -> dict:
        return {p: {'configured': self.configured(p), 'missing': list(self.missing(p)),
                    'sources': {f: self.__sources[f] for f in fields if f in self.__sources}}
                for p, fields in sorted(self.__providers.items())}

    def __repr__(self) -> str:
        return '<Credentials: values hidden>'

    def __reduce_ex__(self, protocol):
        raise TypeError('Credential serialization is disabled')
