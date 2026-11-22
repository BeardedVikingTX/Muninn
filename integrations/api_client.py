"""Opt-in JSON client for explicitly configured public provider operations.
Trusted local endpoint registry only; no target URLs, redirects or implicit retries.
Authentication probes are endpoint-specific, not universal key validation.
"""
from __future__ import annotations
import http.client
import json
import re
import ssl
import threading
from dataclasses import dataclass, field
from types import MappingProxyType
from urllib.parse import urlencode
from .credentials import Credentials, CredentialError, DEFAULT_PROVIDERS
from .quota_manager import QuotaManager
from .response_cache import ResponseCache, CacheError

@dataclass(frozen=True)
class Operation:
    provider: str
    name: str
    host: str
    path: str
    credential_field: str
    auth_header: str = 'Authorization'
    auth_prefix: str = 'Bearer '
    query_fields: tuple[str, ...] = ()
    ttl: int = 0
    probe: bool = False
    def __post_init__(self):
        if not re.fullmatch(r'[a-z0-9_]+', self.provider) or not re.fullmatch(r'[a-z0-9_]+', self.name):
            raise ValueError('Invalid operation identity')
        if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}', self.host):
            raise ValueError('Invalid provider hostname')
        if not re.fullmatch(r'/[A-Za-z0-9_./-]*', self.path) or self.path.startswith('//') or '..' in self.path:
            raise ValueError('Invalid provider path')
        if self.credential_field not in DEFAULT_PROVIDERS.get(self.provider, ()):
            raise ValueError('Credential does not belong to provider')
        if self.auth_header.lower() not in {'authorization','x-api-key','api-key','apikey','x-goog-api-key','key'}:
            raise ValueError('Unsupported authentication header')
        if self.auth_prefix not in {'', 'Bearer ', 'Basic '}:
            raise ValueError('Unsupported authentication prefix')
        if type(self.ttl) is not int or not 0 <= self.ttl <= 86400 or (self.probe and self.ttl):
            raise ValueError('Invalid cache policy')
        if not isinstance(self.query_fields, tuple) or any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', k) for k in self.query_fields):
            raise ValueError('Invalid query schema')

# Candidate read-only probes; review provider documentation and billing before enabling.
DEFAULT_OPERATIONS = (
    Operation('groq','health','api.groq.com','/openai/v1/models','GROQ_API_KEY',probe=True),
    Operation('mistral','health','api.mistral.ai','/v1/models','MISTRAL_API_KEY',probe=True),
    Operation('cerebras','health','api.cerebras.ai','/v1/models','CEREBRAS_API_KEY',probe=True),
    Operation('deepseek','health','api.deepseek.com','/models','DEEPSEEK_API_KEY',probe=True),
    Operation('gemini','health','generativelanguage.googleapis.com','/v1beta/models','GEMINI_API_KEY','x-goog-api-key','',probe=True),
    Operation('openrouter','health','openrouter.ai','/api/v1/key','OPENROUTER_API_KEY',probe=True),
    Operation('nvd','cve_lookup','services.nvd.nist.gov','/rest/json/cves/2.0','NVD_API_KEY','apiKey','',('cveId',),3600),
)

@dataclass(frozen=True)
class Result:
    status: str
    http_status: int | None = None
    data: object = field(default=None, repr=False)
    cached: bool = False
    retry_after: float | None = None

class APIClient:
    def __init__(self, credentials: Credentials, quota: QuotaManager, cache: ResponseCache | None = None, *, operations=DEFAULT_OPERATIONS, online=False, timeout=8, max_bytes=1024*1024):
        if type(online) is not bool or type(timeout) is not int or not 1 <= timeout <= 30 or type(max_bytes) is not int or not 1 <= max_bytes <= 4*1024*1024:
            raise ValueError('Invalid transport configuration')
        registry = {}
        for op in operations:
            if not isinstance(op, Operation) or (op.provider,op.name) in registry:
                raise ValueError('Invalid or duplicate operation')
            registry[op.provider,op.name] = op
        self.operations = MappingProxyType(registry)
        self.credentials, self.quota, self.cache = credentials, quota, cache
        self.online, self.timeout, self.max_bytes = online, timeout, max_bytes
        self._locks = tuple(threading.Lock() for _ in range(64))

    def inventory(self):
        return {p: {'configured': s['configured'], 'probe_available': any(o.provider == p and o.probe for o in self.operations.values())} for p,s in self.credentials.status().items()}

    def check(self, provider):
        if provider not in self.credentials.status(): return Result("unknown_provider")
        if not self.credentials.configured(provider):
            return Result('not_configured')
        op = next((o for o in self.operations.values() if o.provider == provider and o.probe), None)
        if op is None: return Result('probe_not_implemented')
        result = self.request(provider, op.name)
        # Do not expose account metadata from health probes.
        return Result(result.status, result.http_status, retry_after=result.retry_after)

    def request(self, provider, operation, *, parameters=None):
        op = self.operations.get((provider, operation))
        if op is None: return Result('operation_not_registered')
        params = {} if parameters is None else parameters
        if not isinstance(params, dict) or set(params) != set(op.query_fields) or any(not isinstance(v,str) or len(v)>128 or any(ord(c)<32 or ord(c)>126 for c in v) for v in params.values()):
            return Result('invalid_parameters')
        if 'cveId' in params and not re.fullmatch(r'CVE-\d{4}-\d{4,}', params['cveId']):
            return Result('invalid_parameters')
        key = None
        if self.cache is not None and op.ttl:
            try: key = self.cache.key(provider, operation, {'host':op.host,'path':op.path,'query':params}, version='v1', public=True)
            except CacheError: return Result('cache_error')
        with self._locks[hash(key or (provider,operation)) % len(self._locks)]:
            if key is not None:
                try:
                    hit = self.cache.get(key)
                    if hit is not None: return Result('ok',200,hit.value,True)
                except Exception: return Result('cache_error')
            if not self.online: return Result('offline')
            if not self.credentials.configured(provider): return Result('not_configured')
            try: secret = self.credentials.reveal(op.credential_field)
            except CredentialError: return Result('not_configured')
            if not secret.isascii() or any(ord(c)<33 or ord(c)>126 for c in secret): return Result('invalid_credential_format')
            policy = self.quota.policies.get(provider)
            if policy is None or policy.lease_seconds <= self.timeout * 4: return Result('quota_policy_unavailable')
            try: decision = self.quota.reserve(provider)
            except Exception: return Result('quota_error')
            if not decision.allowed: return Result('quota_denied',retry_after=decision.retry_after)
            try:
                result = self._send(op, params, secret)
                if result.http_status == 429:
                    self.quota.cooldown(provider, result.retry_after or 60)
                if result.status == 'ok' and key is not None:
                    # Only public, explicitly registered operations are cacheable.
                    try: self.cache.put(key,result.data,ttl=op.ttl,public=True)
                    except Exception: pass
                return result
            except Exception: return Result('internal_error')
            finally:
                try: self.quota.finish(decision.lease_id)
                except Exception: pass # Lease expires conservatively; no refund.

    def _send(self, op, params, secret):
        conn = None
        try:
            conn = http.client.HTTPSConnection(op.host,443,timeout=self.timeout,context=ssl.create_default_context())
            path = op.path + ('?' + urlencode(params) if params else '')
            conn.request('GET',path,headers={op.auth_header:op.auth_prefix+secret,'Accept':'application/json','Accept-Encoding':'identity','User-Agent':'Muninn/0.1'})
            response = conn.getresponse()
            code = response.status
            if code == 429:
                retry = response.getheader('Retry-After','')
                delay = min(86400,max(1,int(retry))) if retry.isascii() and retry.isdigit() and len(retry)<=10 else 60
                return Result('rate_limited',code,retry_after=delay)
            if code != 200:
                status = {401:'authentication_rejected',403:'access_denied',402:'payment_required',404:'endpoint_not_found'}.get(code,'redirect_blocked' if 300<=code<400 else 'provider_error')
                return Result(status,code)
            if response.getheader('Content-Encoding','identity').lower() != 'identity': return Result('unsupported_encoding',code)
            if 'json' not in response.getheader('Content-Type','').lower(): return Result('unexpected_content_type',code)
            raw = response.read(self.max_bytes+1)
            if len(raw)>self.max_bytes: return Result('response_too_large',code)
            try: data = json.loads(raw,parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            except (ValueError,RecursionError): return Result('invalid_json',code)
            return Result('ok',code,data)
        except ssl.SSLError: return Result('tls_error')
        except TimeoutError: return Result('timeout')
        except (OSError,http.client.HTTPException): return Result('transport_error')
        finally:
            if conn is not None: conn.close()
