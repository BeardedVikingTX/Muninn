"""Offline HTTP scope classification. Local configuration is not proof of permission.
No network access. Python 3.10+, PyYAML for loading files.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
import re
import hashlib
from core.confidence import ScopeStatus

class ScopeError(ValueError):
    pass

_HOST = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
_SEVERITIES = ('low', 'medium', 'high', 'critical')

def _host(value: str) -> str:
    if not isinstance(value, str) or not value.isascii():
        raise ScopeError('Only ASCII DNS names are supported (use punycode)')
    value = value.lower()
    if len(value) > 253 or not all(_HOST.fullmatch(x) for x in value.split('.')):
        raise ScopeError('Invalid DNS name')
    if value.split('.')[-1].isdigit():
        raise ScopeError('IP literals and numeric suffixes are unsupported')
    return value

def _url(value: str):
    if not isinstance(value, str) or len(value) > 16384 or not value.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in value) or '\\' in value or '#' in value:
        raise ScopeError('Invalid or ambiguous URL')
    try:
        p = urlsplit(value)
        if p.scheme not in ('http','https') or not p.netloc or '@' in p.netloc or '%' in p.netloc or p.hostname is None:
            raise ScopeError('Expected HTTP(S) URL without credentials')
        host = _host(p.hostname)
        port = p.port
        if port is not None and not 1 <= port <= 65535:
            raise ScopeError('Invalid port')
        if p.netloc.lower() != host + (f':{port}' if port is not None else ''):
            raise ScopeError('Ambiguous authority')
        return p.scheme, host, port or (443 if p.scheme == 'https' else 80), p.path or '/', p.query
    except ValueError as exc:
        raise ScopeError('Invalid HTTP URL') from exc

@dataclass(frozen=True, slots=True)
class ScopeDecision:
    status: ScopeStatus
    reason: str
    rule: str | None = None
    eligible: bool | None = None
    max_severity: str | None = None
    bounty_table: str | None = None
    # Never grants permission to issue traffic.
    active_allowed: bool = False

@dataclass(frozen=True, slots=True)
class _Rule:
    kind: str
    value: str
    section: str
    key: object
    eligible: bool | None
    severity: str | None
    table: str | None

    def matches(self, target):
        scheme, host, port, path, query = target
        if self.kind == 'url':
            return target == self.key
        if self.kind == 'host':
            return host == self.key
        if self.kind == 'domain':
            return host == self.key or host.endswith('.' + self.key)
        if self.kind == 'wildcard':
            return host.endswith('.' + self.key)
        if self.kind == 'wildcard_scheme':
            s, h = self.key
            return scheme == s and host.endswith('.' + h)
        return False

    def rank(self):
        return ({'host': 5, 'url': 4, 'wildcard_scheme': 3, 'wildcard': 2, 'domain': 1}.get(self.kind,0), len(str(self.key)))

@dataclass(frozen=True, slots=True)
class ScopeEngine:
    program: str
    rules: tuple[_Rule, ...]
    ineligible_classes: frozenset[str]
    max_rps: int | None = None
    policy_digest: str | None = None

    @classmethod
    def from_mapping(cls, data, *, policy_digest=None):
        if not isinstance(data, dict) or not isinstance(data.get('program'), str) or not data['program'].strip():
            raise ScopeError('Missing program name')
        tables = data.get('bounty_tables', {})
        if not isinstance(tables, dict):
            raise ScopeError('Invalid bounty tables')
        for name, table in tables.items():
            if not isinstance(name,str) or not isinstance(table,dict):
                raise ScopeError('Invalid bounty table')
            for severity, bounds in table.items():
                if severity not in _SEVERITIES or not isinstance(bounds,list) or len(bounds)!=2 or any(type(x) is not int or x<0 for x in bounds) or bounds[0]>bounds[1]:
                    raise ScopeError('Invalid bounty range')
        rules = []
        seen = set()
        for section in ('excluded_assets','out_of_scope','in_scope'):
            entries = data.get(section, [] if section == 'excluded_assets' else None)
            if not isinstance(entries,list):
                raise ScopeError(f'Missing or invalid {section}')
            for entry in entries:
                if not isinstance(entry,dict):
                    raise ScopeError('Invalid rule')
                k,v = entry.get('kind'),entry.get('value')
                if not isinstance(k,str) or not isinstance(v,str) or not v or len(v)>16384:
                    raise ScopeError('Invalid rule kind/value')
                if k in ('android','ios','other') and section == 'in_scope':
                    continue  # Non-HTTP assets cannot authorize HTTP traffic.
                if k in ('host','domain'):
                    key = _host(v)
                elif k == 'wildcard' and v.startswith('*.'):
                    key = _host(v[2:])
                elif k == 'wildcard_scheme' and re.fullmatch(r'https?://\*\.[a-zA-Z0-9.-]+',v):
                    s,h = v.split('://*.'); key = (s,_host(h))
                elif k == 'url':
                    key = _url(v)
                else:
                    raise ScopeError('Unsupported or malformed HTTP scope rule: '+k)
                marker = (section,k,key)
                if marker in seen:
                    raise ScopeError('Duplicate scope rule')
                seen.add(marker)
                eligible = entry.get('eligible')
                severity = entry.get('max_severity')
                table = entry.get('bounty_table')
                if eligible is not None and type(eligible) is not bool:
                    raise ScopeError('Invalid eligibility')
                if severity is not None and severity not in _SEVERITIES:
                    raise ScopeError('Invalid severity cap')
                if table is not None and (not isinstance(table,str) or table not in tables):
                    raise ScopeError('Unknown bounty table')
                rules.append(_Rule(k,v,section,key,eligible,severity,table))
        classes = data.get('core_ineligible',[])
        if not isinstance(classes,list) or any(not isinstance(x,str) or not x for x in classes):
            raise ScopeError('Invalid ineligible classes')
        rate = data.get('rate_limit',{})
        if not isinstance(rate,dict):
            raise ScopeError('Invalid rate limit')
        rps = rate.get('max_rps')
        if rps is not None and (type(rps) is not int or rps <= 0):
            raise ScopeError('Invalid max_rps')
        return cls(data['program'],tuple(rules),frozenset(classes),rps,policy_digest)

    @classmethod
    def from_yaml(cls, path):
        import yaml
        class Loader(yaml.SafeLoader):
            def compose_node(self, parent, index):
                if self.check_event(yaml.AliasEvent):
                    raise ScopeError('YAML aliases are unsupported')
                return super().compose_node(parent,index)
            def construct_mapping(self,node,deep=False):
                result = {}
                for k,v in node.value:
                    key = self.construct_object(k,deep=deep)
                    if not isinstance(key,str) or key in result:
                        raise ScopeError('Invalid or duplicate YAML key')
                    result[key] = self.construct_object(v,deep=deep)
                return result
        with Path(path).open('rb') as f:
            raw = f.read(1048577)
        if len(raw)>1048576:
            raise ScopeError('Scope file exceeds size limit')
        try:
            data = yaml.load(raw,Loader=Loader)
        except (yaml.YAMLError,RecursionError) as exc:
            raise ScopeError('Invalid YAML') from exc
        return cls.from_mapping(data,policy_digest=hashlib.sha256(raw).hexdigest())

    def classify(self, url: str, *, category: str | None = None) -> ScopeDecision:
        try:
            target = _url(url)
        except ScopeError:
            return ScopeDecision(ScopeStatus.UNKNOWN,'Malformed or unsupported HTTP target')
        matches = [r for r in self.rules if r.matches(target)]
        # Explicit prohibitions override exclusions, conservatively.
        for section in ('out_of_scope','excluded_assets','in_scope'):
            candidates = [r for r in matches if r.section == section]
            if not candidates:
                continue
            best = max(r.rank() for r in candidates)
            winners = [r for r in candidates if r.rank()==best]
            if len(winners)!=1:
                return ScopeDecision(ScopeStatus.UNKNOWN,'Ambiguous matching rules')
            r = winners[0]
            if section == 'out_of_scope':
                return ScopeDecision(ScopeStatus.PROHIBITED,'Explicit prohibition',r.value,False)
            if section == 'excluded_assets':
                return ScopeDecision(ScopeStatus.UNKNOWN,'Excluded asset; manual policy review required',r.value,False)
            eligible = False if category in self.ineligible_classes else r.eligible
            # ScopeStatus.AUTHORIZED is reserved for independently verified permission.
            return ScopeDecision(ScopeStatus.UNKNOWN,'Local in-scope match; permission not independently verified',r.value,eligible,r.severity,r.table)
        return ScopeDecision(ScopeStatus.PROHIBITED,'No matching HTTP inclusion',eligible=False)
