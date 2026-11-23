import json
import unittest
from audit.cors import CORSAuditor, CORSConfig, CORSCapture, _origin

URL = 'https://api.example.test/private?token=secret'
EVIL = 'https://attacker.example'

def cap(origin=EVIL, acao=EVIL, creds='true', **kwargs):
    return CORSCapture('GET', URL, 200,
        {'Origin': origin},
        {'Access-Control-Allow-Origin': acao, 'Access-Control-Allow-Credentials': creds},
        **kwargs)

def run(captures, **cfg):
    return CORSAuditor(CORSConfig(**cfg)).analyze(captures, scope_check=lambda u: True)

def codes(report):
    return {f.code for f in report.findings}

class CorsTests(unittest.TestCase):
    def test_origin_normalize(self): self.assertEqual(_origin('HTTPS://EXAMPLE.TEST:443'), 'https://example.test')
    def test_origin_http_port(self): self.assertEqual(_origin('http://a.test:8080'), 'http://a.test:8080')
    def test_origin_null(self): self.assertEqual(_origin('null'), 'null')
    def test_origin_reject_path(self): self.assertIsNone(_origin('https://a.test/evil'))
    def test_origin_reject_userinfo(self): self.assertIsNone(_origin('https://u:p@a.test'))
    def test_origin_reject_javascript(self): self.assertIsNone(_origin('javascript:alert(1)'))
    def test_origin_reject_bad_port(self): self.assertIsNone(_origin('https://a.test:xyz'))
    def test_missing_scope_callback(self):
        with self.assertRaises(TypeError): CORSAuditor().analyze([cap()], scope_check=None)
    def test_scope_excluded(self):
        r = CORSAuditor().analyze([cap()], scope_check=lambda _: False)
        self.assertEqual((r.analyzed,r.skipped), (0,1))
    def test_scope_error_fails_closed(self):
        def fail(_): raise RuntimeError()
        self.assertEqual(CORSAuditor().analyze([cap()], scope_check=fail).skipped,1)
    def test_untrusted_credentialed(self):
        self.assertIn('UNTRUSTED_CREDENTIALED_ORIGIN', codes(run([cap(sensitive=True)], untrusted_origins=frozenset({EVIL}))))
    def test_untrusted_not_assumed(self):
        self.assertNotIn('UNTRUSTED_CREDENTIALED_ORIGIN', codes(run([cap()])))
    def test_untrusted_noncredentialed(self):
        self.assertNotIn('UNTRUSTED_CREDENTIALED_ORIGIN', codes(run([cap(creds='false')], untrusted_origins=frozenset({EVIL}))))
    def test_public_sensitive_read(self):
        self.assertIn('UNTRUSTED_PUBLIC_READ', codes(run([cap(creds='false', sensitive=True)], untrusted_origins=frozenset({EVIL}))))
    def test_wildcard_credentials_not_exploitable(self):
        r=run([cap(acao='*')], untrusted_origins=frozenset({EVIL}))
        self.assertIn('WILDCARD_WITH_CREDENTIALS',codes(r))
        self.assertNotIn('UNTRUSTED_CREDENTIALED_ORIGIN',codes(r))
    def test_null_credentials(self):
        self.assertIn('NULL_ORIGIN_WITH_CREDENTIALS', codes(run([cap(origin='null',acao='null')])))
    def test_insecure_origin(self):
        self.assertIn('INSECURE_ORIGIN_TRUST',codes(run([cap(origin='http://a.test',acao='http://a.test')])))
    def test_invalid_allow_origin(self):
        self.assertIn('INVALID_ALLOW_ORIGIN',codes(run([cap(acao='https://a.test, https://b.test')])))
    def test_vary_missing(self):
        self.assertIn('MISSING_VARY_ORIGIN',codes(run([cap()])))
    def test_vary_present(self):
        c=cap(); h=dict(c.response_headers); h['Vary']='Accept-Encoding, Origin'
        c=CORSCapture(c.method,c.url,c.status,c.request_headers,h)
        self.assertNotIn('MISSING_VARY_ORIGIN',codes(run([c])))
    def test_no_store(self):
        c=cap(); h=dict(c.response_headers); h['Cache-Control']='private, no-store'
        c=CORSCapture(c.method,c.url,c.status,c.request_headers,h)
        self.assertNotIn('MISSING_VARY_ORIGIN',codes(run([c])))
    def test_preflight_method_rejected(self):
        c=CORSCapture('OPTIONS',URL,204,{'Origin':EVIL,'Access-Control-Request-Method':'DELETE'},
            {'Access-Control-Allow-Origin':EVIL,'Access-Control-Allow-Methods':'GET, POST'})
        self.assertIn('PREFLIGHT_METHOD_NOT_ALLOWED',codes(run([c])))
    def test_preflight_headers_rejected(self):
        c=CORSCapture('OPTIONS',URL,204,{'Origin':EVIL,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'X-Custom'},
            {'Access-Control-Allow-Origin':EVIL,'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Content-Type'})
        self.assertIn('PREFLIGHT_HEADERS_NOT_ALLOWED',codes(run([c])))
    def test_multiple_origins(self):
        r=run([cap(),cap(origin='https://other.example',acao='https://other.example')], untrusted_origins=frozenset({EVIL}))
        self.assertIn('MULTI_ORIGIN_REFLECTION',codes(r))
    def test_no_multiple_without_untrusted(self):
        self.assertNotIn('MULTI_ORIGIN_REFLECTION',codes(run([cap(),cap(origin='https://other.example',acao='https://other.example')])))
    def test_query_not_reported(self):
        self.assertNotIn('secret',run([cap()]).to_json())
    def test_bounded_captures(self):
        r=run([cap(),cap()],max_captures=1)
        self.assertEqual(r.analyzed,1); self.assertTrue(r.truncated)
    def test_bounded_findings(self):
        r=run([cap(sensitive=True)],max_findings=1,untrusted_origins=frozenset({EVIL}))
        self.assertEqual(len(r.findings),1); self.assertTrue(r.truncated)
    def test_limits_positive(self):
        with self.assertRaises(ValueError): CORSConfig(max_captures=0)
    def test_policy_origin_canonical(self):
        with self.assertRaises(ValueError): CORSConfig(untrusted_origins=frozenset({'HTTPS://A.TEST'}))
    def test_deterministic_json(self):
        self.assertEqual(run([cap()]).to_json(),run([cap()]).to_json())
    def test_json_valid(self):
        self.assertIsInstance(json.loads(run([cap()]).to_json())['findings'],list)
    def test_deduplication(self):
        self.assertEqual(len(run([cap(),cap()]).findings),len(run([cap()]).findings))
    def test_invalid_url_skipped(self):
        c=CORSCapture('GET','file:///etc/passwd',200)
        self.assertEqual(run([c]).skipped,1)

if __name__ == '__main__': unittest.main()

