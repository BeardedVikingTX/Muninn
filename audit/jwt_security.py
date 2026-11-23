"""Muninn JWT security auditing: offline, non-invasive, standard-library only.

Never treats decoded claims as authenticated. Does not transmit or forge tokens.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable, Mapping

_TOKEN_RE = re.compile(r'(?<![A-Za-z0-9_-])(?:eyJ[A-Za-z0-9_-]{5,}\.){2}[A-Za-z0-9_-]+(?![A-Za-z0-9_-])')
_SENSITIVE = {'sub','email','name','phone','address','token','secret','password','access_token','refresh_token'}


def _decode(segment: str, limit: int = 65536) -> bytes:
    if not segment or len(segment) > limit * 2 or not re.fullmatch(r'[A-Za-z0-9_-]+', segment):
        raise ValueError('invalid base64url segment')
    try:
        raw = base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))
    except Exception as exc:
        raise ValueError('invalid base64url encoding') from exc
    if len(raw) > limit or base64.urlsafe_b64encode(raw).decode().rstrip('=') != segment:
        raise ValueError('noncanonical or oversized base64url')
    return raw


def _object(segment: str) -> dict[str, Any]:
    def no_duplicates(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError('duplicate JSON member')
            out[k] = v
        return out
    try:
        result = json.loads(_decode(segment), object_pairs_hook=no_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('invalid JWT JSON') from exc
    if not isinstance(result, dict):
        raise ValueError('JWT section must be JSON object')
    return result


@dataclass(frozen=True)
class JWTPolicy:
    allowed_algorithms: frozenset[str] = frozenset({'HS256', 'RS256', 'ES256', 'EdDSA'})
    expected_issuer: str | None = None
    expected_audience: str | None = None
    require_expiration: bool = True
    require_issuer: bool = False
    require_audience: bool = False
    clock_skew_seconds: int = 60
    max_lifetime_seconds: int | None = 3600
    max_tokens: int = 10000
    max_findings: int = 10000


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    token_id: str
    detail: str


@dataclass
class JWTReport:
    tokens_examined: int = 0
    findings: list[Finding] = field(default_factory=list)
    invalid_tokens: int = 0

    def to_json(self) -> str:
        return json.dumps({'tokens_examined': self.tokens_examined,
                           'invalid_tokens': self.invalid_tokens,
                           'findings': [asdict(f) for f in self.findings]}, sort_keys=True)


@dataclass(frozen=True)
class ParsedJWT:
    header: Mapping[str, Any]
    claims: Mapping[str, Any]
    signature: bytes
    signing_input: bytes
    token_id: str

    def safe_summary(self) -> dict[str, Any]:
        return {'token_id': self.token_id,
                'algorithm': self.header.get('alg'),
                'claim_names': sorted(self.claims.keys()),
                'header_names': sorted(self.header.keys()),
                'signature_present': bool(self.signature)}


def parse_jwt(token: str) -> ParsedJWT:
    if not isinstance(token, str) or len(token) > 131072:
        raise ValueError('invalid JWT length')
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('compact JWT must have three segments')
    header, claims = _object(parts[0]), _object(parts[1])
    if not isinstance(header.get('alg'), str):
        raise ValueError('missing or invalid alg')
    signature = _decode(parts[2]) if parts[2] else b''
    return ParsedJWT(header, claims, signature, (parts[0] + '.' + parts[1]).encode('ascii'),
                     hashlib.sha256(token.encode('ascii')).hexdigest()[:20])


def verify_hmac(token: str, key: bytes, *, allowed_algorithms: Iterable[str] = ('HS256',)) -> bool:
    """Verify an HMAC JWT against an explicitly supplied trusted key; never infer keys from tokens."""
    parsed = parse_jwt(token)
    alg = parsed.header['alg']
    hashes = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}
    if alg not in hashes or alg not in set(allowed_algorithms) or not isinstance(key, bytes) or not key:
        return False
    expected = hmac.new(key, parsed.signing_input, hashes[alg]).digest()
    return hmac.compare_digest(expected, parsed.signature)


def _timestamp(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not -1e12 < value < 1e12:
        return None
    return float(value)


class JWTSecurityAuditor:
    def __init__(self, policy: JWTPolicy | None = None):
        self.policy = policy or JWTPolicy()

    def analyze(self, tokens: Iterable[str], *, now: float | None = None) -> JWTReport:
        now = time.time() if now is None else now
        report = JWTReport()
        seen = set()
        def add(code: str, severity: str, token_id: str, detail: str):
            if len(report.findings) < self.policy.max_findings:
                report.findings.append(Finding(code, severity, token_id, detail))
        for token in tokens:
            if report.tokens_examined >= self.policy.max_tokens:
                break
            report.tokens_examined += 1
            token_id = hashlib.sha256(str(token).encode('utf-8', errors='replace')).hexdigest()[:20]
            if token_id in seen:
                continue
            seen.add(token_id)
            try:
                jwt = parse_jwt(token)
            except (ValueError, UnicodeError):
                report.invalid_tokens += 1
                add('MALFORMED_JWT', 'info', token_id, 'JWT structure or encoding invalid')
                continue
            alg = jwt.header['alg']
            if alg == 'none':
                add('UNSIGNED_JWT', 'high', token_id, 'JWT declares no signing algorithm; acceptance not established')
            elif alg not in self.policy.allowed_algorithms:
                add('UNAPPROVED_ALGORITHM', 'medium', token_id, 'Algorithm not on explicit allowlist')
            if alg != 'none' and not jwt.signature:
                add('MISSING_SIGNATURE', 'high', token_id, 'Signature segment is empty')
            if alg == 'none' and jwt.signature:
                add('UNEXPECTED_SIGNATURE', 'low', token_id, 'Unsigned JWT has a signature segment')
            for key in ('jku', 'x5u'):
                if key in jwt.header:
                    add('REMOTE_KEY_REFERENCE', 'medium', token_id, f'Header contains {key}; ensure verifier uses trusted allowlisted keys')
            if 'jwk' in jwt.header:
                add('EMBEDDED_JWK', 'medium', token_id, 'Header embeds a key; do not trust attacker-supplied verification keys')
            if 'crit' in jwt.header or jwt.header.get('b64') is False:
                add('SPECIAL_HEADER', 'medium', token_id, 'Critical or unencoded-payload header requires explicit verifier support')
            exp = _timestamp(jwt.claims.get('exp'))
            nbf = _timestamp(jwt.claims.get('nbf'))
            iat = _timestamp(jwt.claims.get('iat'))
            if 'exp' not in jwt.claims:
                if self.policy.require_expiration:
                    add('MISSING_EXPIRATION', 'medium', token_id, 'Expiration claim missing')
            elif exp is None:
                add('INVALID_EXPIRATION', 'medium', token_id, 'Expiration must be numeric')
            elif exp < now - self.policy.clock_skew_seconds:
                add('EXPIRED', 'info', token_id, 'Token is expired; server acceptance not established')
            if 'nbf' in jwt.claims and nbf is None:
                add('INVALID_NOT_BEFORE', 'medium', token_id, 'Not-before must be numeric')
            elif nbf is not None and nbf > now + self.policy.clock_skew_seconds:
                add('NOT_YET_VALID', 'info', token_id, 'Token not yet valid')
            if 'iat' in jwt.claims and iat is None:
                add('INVALID_ISSUED_AT', 'medium', token_id, 'Issued-at must be numeric')
            elif iat is not None and iat > now + self.policy.clock_skew_seconds:
                add('FUTURE_ISSUED_AT', 'low', token_id, 'Issued-at is in the future')
            if exp is not None and iat is not None:
                if exp < iat:
                    add('INVALID_LIFETIME', 'medium', token_id, 'Expiration precedes issuance')
                elif self.policy.max_lifetime_seconds is not None and exp - iat > self.policy.max_lifetime_seconds:
                    add('LONG_LIFETIME', 'low', token_id, 'Lifetime exceeds configured policy')
            iss = jwt.claims.get('iss')
            if self.policy.require_issuer and not isinstance(iss, str):
                add('MISSING_ISSUER', 'medium', token_id, 'Required issuer missing')
            if self.policy.expected_issuer is not None and iss != self.policy.expected_issuer:
                add('ISSUER_MISMATCH', 'medium', token_id, 'Issuer does not match configured trust policy')
            aud = jwt.claims.get('aud')
            if self.policy.require_audience and aud is None:
                add('MISSING_AUDIENCE', 'medium', token_id, 'Required audience missing')
            if self.policy.expected_audience is not None:
                audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
                if self.policy.expected_audience not in audiences:
                    add('AUDIENCE_MISMATCH', 'medium', token_id, 'Audience does not match configured trust policy')
        return report


def discover_jwts(text: str, *, max_bytes: int = 2_000_000, max_tokens: int = 1000) -> list[str]:
    """Discover JWT-looking strings from authorized captures; values remain in caller memory."""
    if not isinstance(text, str):
        raise TypeError('text must be str')
    return list(dict.fromkeys(_TOKEN_RE.findall(text[:max_bytes])))[:max_tokens]
