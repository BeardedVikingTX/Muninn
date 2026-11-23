"""Muninn offline OAuth 2.0 / OpenID Connect security auditor.

Analyzes authorized, pre-captured transactions. Never sends network requests,
redeems codes, or changes accounts. Findings are review signals, not proof of exploit.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
from urllib.parse import urlsplit, parse_qs
import json
import re
from typing import Callable, Iterable, Mapping, Optional

SENSITIVE = re.compile(r'(?i)(token|secret|password|authorization|cookie|code|assertion|credential|state|nonce|verifier)')


def fingerprint(value: str) -> str:
    return sha256(value.encode('utf-8', errors='replace')).hexdigest()[:16]


def _params(url: str) -> dict[str, str]:
    parts = urlsplit(url)
    return {k: v[-1] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}


def _safe_location(url: str) -> str:
    parts = urlsplit(url)
    return f'{parts.scheme}://{parts.netloc}{parts.path}'


def _body_params(body: str, content_type: str) -> dict[str, str]:
    if len(body) > 131072:
        return {}
    if 'application/json' in content_type.lower():
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                return {str(k): str(v) for k, v in obj.items() if isinstance(v, (str, int, bool))}
        except (ValueError, TypeError):
            pass
    if 'application/x-www-form-urlencoded' in content_type.lower():
        return {k: v[-1] for k, v in parse_qs(body, keep_blank_values=True).items()}
    return {}


@dataclass(frozen=True)
class OAuthCapture:
    url: str
    method: str = 'GET'
    phase: str = 'authorization'  # authorization, callback, token, metadata
    status: int = 200
    request_headers: Mapping[str, str] = field(default_factory=dict)
    request_body: str = ''
    response_headers: Mapping[str, str] = field(default_factory=dict)
    response_body: str = ''
    transaction_id: str = ''  # nonsecret, trusted test correlation identifier
    expected_state: Optional[str] = None  # trusted test fixture only
    expected_nonce: Optional[str] = None  # trusted test fixture only
    pkce_required: bool = False
    oidc_required: bool = False
    trusted_token_claims: Optional[Mapping[str, object]] = None
    expected_issuer: Optional[str] = None
    expected_audience: Optional[str] = None
    verified_token_signature: bool = False


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    confidence: str
    endpoint: str
    evidence: str
    transaction: str = ''


@dataclass(frozen=True)
class OAuthReport:
    analyzed: int
    findings: tuple[Finding, ...]
    skipped_out_of_scope: int
    def to_json(self) -> str:
        return json.dumps({'analyzed': self.analyzed,
                           'skipped_out_of_scope': self.skipped_out_of_scope,
                           'findings': [asdict(f) for f in self.findings]},
                          sort_keys=True, separators=(',', ':'))


class OAuthOIDCAuditor:
    def __init__(self, *, max_captures: int = 10000, max_findings: int = 3000,
                 max_body_bytes: int = 131072):
        if min(max_captures, max_findings, max_body_bytes) <= 0:
            raise ValueError('limits must be positive')
        self.max_captures = max_captures
        self.max_findings = max_findings
        self.max_body_bytes = max_body_bytes

    def analyze(self, captures: Iterable[OAuthCapture], *,
                scope_check: Callable[[str], bool]) -> OAuthReport:
        if not callable(scope_check):
            raise TypeError('scope_check must be callable')
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        analyzed = skipped = 0
        for index, capture in enumerate(captures):
            if index >= self.max_captures:
                break
            parts = urlsplit(capture.url)
            if parts.scheme not in ('https', 'http') or not parts.netloc:
                skipped += 1
                continue
            if not scope_check(capture.url):
                skipped += 1
                continue
            analyzed += 1
            endpoint = _safe_location(capture.url)
            tx = fingerprint(capture.transaction_id) if capture.transaction_id else ''
            def emit(code: str, severity: str, confidence: str, evidence: str) -> None:
                key = (code, endpoint, tx)
                if key not in seen and len(findings) < self.max_findings:
                    seen.add(key)
                    findings.append(Finding(code, severity, confidence, endpoint, evidence, tx))

            query = _params(capture.url)
            headers = {str(k).lower(): str(v) for k, v in capture.request_headers.items()}
            rh = {str(k).lower(): str(v) for k, v in capture.response_headers.items()}
            body = capture.request_body[:self.max_body_bytes]
            params = {**query, **_body_params(body, headers.get('content-type', ''))}
            phase = capture.phase.lower()

            # URL-carried bearer material is a logging/history/referrer risk.
            for key in ('access_token', 'id_token', 'refresh_token', 'client_secret'):
                if key in query:
                    emit('SENSITIVE_QUERY_PARAMETER', 'high', 'high', f'{key} appears in request URL')
            if 'code' in query and phase != 'callback':
                emit('AUTH_CODE_IN_UNEXPECTED_URL', 'medium', 'medium', 'authorization code in non-callback request URL')
            if parts.scheme == 'http' and phase in ('authorization', 'callback', 'token'):
                emit('INSECURE_TRANSPORT', 'high', 'high', 'OAuth transaction captured over HTTP')

            if phase == 'authorization':
                response_type = params.get('response_type', '')
                if not params.get('state'):
                    emit('MISSING_STATE', 'medium', 'medium', 'authorization request has no state parameter; review transaction binding')
                if 'token' in response_type.split() or 'id_token' in response_type.split():
                    emit('FRONT_CHANNEL_TOKEN', 'medium', 'high', 'authorization response_type requests tokens in browser front channel')
                if capture.pkce_required:
                    if not params.get('code_challenge'):
                        emit('MISSING_PKCE', 'high', 'high', 'PKCE-required authorization request lacks code_challenge')
                    elif params.get('code_challenge_method', 'plain') != 'S256':
                        emit('WEAK_PKCE_METHOD', 'medium', 'high', 'PKCE challenge method is not S256')
                if capture.oidc_required and 'openid' in params.get('scope', '').split() and not params.get('nonce'):
                    # Nonce is especially relevant for implicit/hybrid; not universally mandatory for code flow.
                    if 'id_token' in response_type.split():
                        emit('MISSING_OIDC_NONCE', 'medium', 'medium', 'front-channel ID token request lacks nonce')
                redirect = params.get('redirect_uri', '')
                if redirect:
                    dest = urlsplit(redirect)
                    if dest.scheme == 'http' and dest.hostname not in ('localhost', '127.0.0.1', '::1'):
                        emit('HTTP_REDIRECT_URI', 'high', 'high', 'non-loopback redirect_uri uses HTTP')
                    if dest.fragment:
                        emit('REDIRECT_URI_FRAGMENT', 'low', 'high', 'redirect_uri contains fragment')

            elif phase == 'callback':
                state = params.get('state')
                if capture.expected_state is not None:
                    if not state or state != capture.expected_state:
                        emit('STATE_MISMATCH', 'high', 'high', 'callback state differs from trusted expected state')
                elif ('code' in params or 'id_token' in params) and not state:
                    emit('CALLBACK_MISSING_STATE', 'medium', 'medium', 'callback carries authorization result without state')
                if 'access_token' in query or 'id_token' in query:
                    emit('TOKEN_IN_CALLBACK_QUERY', 'high', 'high', 'token present in callback query string')
                location = rh.get('location', '')
                if location:
                    loc = urlsplit(location)
                    if loc.scheme == 'http' and loc.hostname not in ('localhost', '127.0.0.1', '::1'):
                        emit('INSECURE_CALLBACK_REDIRECT', 'high', 'high', 'callback redirects to non-loopback HTTP destination')

            elif phase == 'token':
                if capture.method.upper() == 'GET':
                    emit('TOKEN_ENDPOINT_GET', 'high', 'high', 'token endpoint accessed using GET')
                if capture.pkce_required and params.get('grant_type') == 'authorization_code' and not params.get('code_verifier'):
                    emit('MISSING_CODE_VERIFIER', 'high', 'high', 'PKCE-required code exchange lacks code_verifier')
                if 'access_token' in capture.response_body[:self.max_body_bytes]:
                    cache = rh.get('cache-control', '').lower()
                    if 'no-store' not in cache:
                        emit('TOKEN_RESPONSE_CACHE_POLICY', 'medium', 'medium', 'token response lacks Cache-Control: no-store')

            elif phase == 'metadata':
                try:
                    metadata = json.loads(capture.response_body[:self.max_body_bytes])
                except (ValueError, TypeError):
                    metadata = None
                if isinstance(metadata, dict):
                    methods = metadata.get('code_challenge_methods_supported', [])
                    if isinstance(methods, list) and methods and 'S256' not in methods:
                        emit('METADATA_NO_S256', 'medium', 'high', 'metadata advertises PKCE methods without S256')
                    algs = metadata.get('id_token_signing_alg_values_supported', [])
                    if isinstance(algs, list) and 'none' in algs:
                        emit('METADATA_UNSIGNED_ID_TOKEN', 'medium', 'high', 'metadata advertises unsigned ID tokens; review client policy')

            # Only evaluate claims that the caller explicitly attests are verified.
            claims = capture.trusted_token_claims
            if claims is not None and capture.verified_token_signature:
                if capture.expected_issuer and claims.get('iss') != capture.expected_issuer:
                    emit('OIDC_ISSUER_MISMATCH', 'high', 'high', 'verified ID token issuer differs from expected issuer')
                if capture.expected_audience:
                    aud = claims.get('aud')
                    audiences = aud if isinstance(aud, list) else [aud]
                    if capture.expected_audience not in audiences:
                        emit('OIDC_AUDIENCE_MISMATCH', 'high', 'high', 'verified ID token audience excludes expected client')
                if capture.expected_nonce is not None and claims.get('nonce') != capture.expected_nonce:
                    emit('OIDC_NONCE_MISMATCH', 'high', 'high', 'verified ID token nonce differs from trusted expected nonce')
            elif claims is not None:
                emit('UNVERIFIED_ID_TOKEN_CLAIMS', 'info', 'high', 'supplied token claims are not signature-verified; no claim assertions performed')

        return OAuthReport(analyzed, tuple(findings), skipped)
