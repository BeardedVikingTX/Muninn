"""Muninn passive open-redirect evidence analyzer (stdlib, no network I/O).

Use only with authorized captures. Reports never include raw query values, URLs,
headers, response bodies, or redirect destinations. External redirects are not
necessarily vulnerabilities: verify the application's intended redirect policy.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
from html import unescape
from html.parser import HTMLParser
import ipaddress
import json
import re
from typing import Callable, Iterable, Mapping
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit

REDIRECT_KEYS = frozenset({"next", "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url", "returnto", "return_to", "continue", "destination", "dest", "target", "goto", "callback", "back", "forward", "r", "to"})
JS_NAV = re.compile(r"(?:\b(?:window\.)?location\s*(?:\.href)?\s*=|\b(?:window\.)?location\.(?:assign|replace)\s*\()\s*(['\"])(.*?)\1", re.I | re.S)
META = re.compile(r"\burl\s*=\s*(['\"]?)([^;'\"\s>]+)\1", re.I)
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _fingerprint(value: str) -> str:
    return sha256(value.encode('utf-8', 'replace')).hexdigest()[:20]


def _host(url: str) -> str | None:
    try:
        p = urlsplit(url)
        if p.scheme.lower() not in ('http', 'https') or not p.netloc:
            return None
        h = p.hostname
        if not h:
            return None
        return h.rstrip('.').encode('idna').decode('ascii').lower()
    except (ValueError, UnicodeError):
        return None


def _site(host: str) -> str:
    """Exact host comparison only; no inaccurate eTLD+1 guessing."""
    return host


def _destination(value: str, base: str) -> tuple[str | None, tuple[str, ...]]:
    """Conservative browser URL approximation; never fetches destination."""
    flags = []
    v = unescape(value).strip()
    if CONTROL.search(v):
        flags.append('control_characters')
    if '\\' in v:
        flags.append('backslashes')
    if '@' in v.split('/', 3)[2:3]:
        flags.append('userinfo')
    for _ in range(3):
        decoded = unquote(v)
        if decoded == v:
            break
        v = decoded
        flags.append('percent_encoding')
    if v.startswith('\\\\'):
        v = '//' + v[2:].replace('\\', '/')
    elif v.startswith('/\\'):
        v = '//' + v[2:].replace('\\', '/')
    if v.startswith('//'):
        flags.append('protocol_relative')
    try:
        target = urljoin(base, v)
    except ValueError:
        return None, tuple(sorted(set(flags + ['invalid_destination'])))
    if _host(target) is None:
        return None, tuple(sorted(set(flags + ['non_http_destination'])))
    try:
        p = urlsplit(target)
        if p.username is not None:
            flags.append('userinfo')
        if p.hostname:
            try:
                ipaddress.ip_address(p.hostname)
                flags.append('ip_literal')
            except ValueError:
                pass
    except ValueError:
        pass
    return target, tuple(sorted(set(flags)))


class _RedirectHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta_urls: list[str] = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() != 'meta':
            return
        a = dict((k.lower(), v or '') for k, v in attrs)
        if a.get('http-equiv', '').lower() == 'refresh':
            match = META.search(a.get('content', ''))
            if match:
                self.meta_urls.append(match.group(2))


@dataclass(frozen=True)
class RedirectCapture:
    url: str
    status: int
    method: str = 'GET'
    response_headers: Mapping[str, str] = field(default_factory=dict)
    response_body: str = ''
    # This optional observation must be supplied by a trusted test harness.
    # It must not be inferred from merely seeing an HTTP 302.
    unauthorized_external_redirect_confirmed: bool = False
    scenario: str = ''


@dataclass(frozen=True)
class RedirectFinding:
    kind: str
    confidence: str
    severity: str
    source_fingerprint: str
    destination_fingerprint: str
    evidence: tuple[str, ...]
    scenario: str = ''


@dataclass(frozen=True)
class RedirectReport:
    examined: int
    skipped_out_of_scope: int
    findings: tuple[RedirectFinding, ...]
    truncated: bool = False
    def to_json(self) -> str:
        return json.dumps({'examined': self.examined, 'skipped_out_of_scope': self.skipped_out_of_scope,
                           'truncated': self.truncated, 'findings': [asdict(f) for f in self.findings]},
                          sort_keys=True, separators=(',', ':'))


class OpenRedirectAuditor:
    def __init__(self, *, max_captures: int = 10000, max_findings: int = 2000,
                 max_body_chars: int = 200000, max_candidate_chars: int = 4096):
        if min(max_captures, max_findings, max_body_chars, max_candidate_chars) < 1:
            raise ValueError('limits must be positive')
        self.max_captures = max_captures
        self.max_findings = max_findings
        self.max_body_chars = max_body_chars
        self.max_candidate_chars = max_candidate_chars

    def analyze(self, captures: Iterable[RedirectCapture], *, scope_check: Callable[[str], bool],
                allowed_redirect_hosts: Iterable[str] = ()) -> RedirectReport:
        if not callable(scope_check):
            raise TypeError('scope_check callback required')
        allowed = {h.rstrip('.').lower() for h in allowed_redirect_hosts}
        findings: list[RedirectFinding] = []
        seen: set[tuple[str, str, str]] = set()
        examined = skipped = 0
        truncated = False
        for i, capture in enumerate(captures):
            if i >= self.max_captures:
                truncated = True
                break
            if not isinstance(capture, RedirectCapture):
                raise TypeError('expected RedirectCapture')
            if not scope_check(capture.url):
                skipped += 1
                continue
            source_host = _host(capture.url)
            if not source_host:
                continue
            examined += 1
            candidates: list[tuple[str, str]] = []
            try:
                query = urlsplit(capture.url).query
                for key, val in parse_qsl(query, keep_blank_values=True, max_num_fields=200):
                    if key.lower() in REDIRECT_KEYS and val:
                        candidates.append(('redirect_parameter', val))
            except ValueError:
                pass
            headers = {str(k).lower(): str(v) for k, v in capture.response_headers.items()}
            if 300 <= capture.status < 400 and headers.get('location'):
                candidates.append(('http_location', headers['location']))
            if len(capture.response_body) <= self.max_body_chars:
                body = capture.response_body
                if 'text/html' in headers.get('content-type', '').lower():
                    parser = _RedirectHTML()
                    try:
                        parser.feed(body)
                        candidates.extend(('meta_refresh', u) for u in parser.meta_urls[:30])
                    except ValueError:
                        pass
                candidates.extend(('javascript_navigation', m.group(2)) for m in list(JS_NAV.finditer(body))[:30])
            for kind, value in candidates[:250]:
                if len(value) > self.max_candidate_chars:
                    continue
                target, flags = _destination(value, capture.url)
                if not target:
                    continue
                dest_host = _host(target)
                if not dest_host or _site(dest_host) == _site(source_host) or dest_host in allowed:
                    continue
                evidence = ['external_destination', f'source_type:{kind}', *flags]
                # A parameter alone is not proof of a redirect.
                observed = kind != 'redirect_parameter'
                if observed:
                    evidence.append('observed_navigation_instruction')
                if capture.unauthorized_external_redirect_confirmed and observed:
                    evidence.append('trusted_unauthorized_redirect_confirmation')
                confidence = ('high' if observed and capture.unauthorized_external_redirect_confirmed
                              else 'medium' if observed else 'low')
                severity = 'medium' if confidence == 'high' else 'informational'
                src_fp, dest_fp = _fingerprint(capture.url), _fingerprint(target)
                identity = (kind, src_fp, dest_fp)
                if identity in seen:
                    continue
                seen.add(identity)
                findings.append(RedirectFinding(kind, confidence, severity, src_fp, dest_fp,
                                                tuple(sorted(set(evidence))),
                                                scenario=capture.scenario[:80]))
                if len(findings) >= self.max_findings:
                    truncated = True
                    break
            if truncated:
                break
        return RedirectReport(examined, skipped, tuple(findings), truncated)
