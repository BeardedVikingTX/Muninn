import json
import unittest
from audit.open_redirect import OpenRedirectAuditor, RedirectCapture, _destination, _host

BASE = 'https://app.example.test/account'
SCOPE = lambda url: url.startswith('https://app.example.test/')

class OpenRedirectTests(unittest.TestCase):
    def setUp(self): self.a = OpenRedirectAuditor()
    def scan(self, *captures, **kw): return self.a.analyze(captures, scope_check=SCOPE, **kw)
    def test_external_location(self):
        r = self.scan(RedirectCapture(BASE, 302, response_headers={'Location':'https://outside.test/x'}))
        self.assertEqual(r.findings[0].confidence, 'medium')
    def test_confirmed(self):
        r = self.scan(RedirectCapture(BASE, 302, response_headers={'Location':'https://outside.test'}, unauthorized_external_redirect_confirmed=True))
        self.assertEqual(r.findings[0].confidence, 'high')
    def test_confirmation_does_not_upgrade_parameter(self):
        r = self.scan(RedirectCapture(BASE+'?next=https://outside.test', 200, unauthorized_external_redirect_confirmed=True))
        self.assertEqual(r.findings[0].confidence, 'low')
    def test_relative_same_host(self):
        self.assertFalse(self.scan(RedirectCapture(BASE, 302, response_headers={'Location':'/dashboard'})).findings)
    def test_absolute_same_host(self):
        self.assertFalse(self.scan(RedirectCapture(BASE, 302, response_headers={'Location':BASE})).findings)
    def test_protocol_relative(self):
        r = self.scan(RedirectCapture(BASE, 302, response_headers={'Location':'//outside.test/path'}))
        self.assertIn('protocol_relative', r.findings[0].evidence)
    def test_encoded_parameter(self):
        r = self.scan(RedirectCapture(BASE+'?next=https%253A%252F%252Foutside.test', 200))
        self.assertEqual(len(r.findings), 1)
    def test_lookalike_domain(self):
        r = self.scan(RedirectCapture(BASE, 302, response_headers={'Location':'https://app.example.test.attacker.test'}))
        self.assertEqual(len(r.findings), 1)
    def test_userinfo(self):
        r = self.scan(RedirectCapture(BASE, 302, response_headers={'Location':'https://app.example.test@outside.test/'}))
        self.assertIn('userinfo', r.findings[0].evidence)
    def test_meta_refresh(self):
        r = self.scan(RedirectCapture(BASE, 200, response_headers={'Content-Type':'text/html'}, response_body='<meta http-equiv="refresh" content="0; url=https://outside.test/x">'))
        self.assertEqual(r.findings[0].kind, 'meta_refresh')
    def test_javascript_navigation(self):
        r = self.scan(RedirectCapture(BASE, 200, response_body='window.location.href = "https://outside.test";'))
        self.assertEqual(r.findings[0].kind, 'javascript_navigation')
    def test_javascript_assign(self):
        r = self.scan(RedirectCapture(BASE, 200, response_body="location.assign('https://outside.test')"))
        self.assertEqual(len(r.findings), 1)
    def test_allowlisted(self):
        r = self.scan(RedirectCapture(BASE, 302, response_headers={'Location':'https://outside.test'}), allowed_redirect_hosts=['outside.test'])
        self.assertFalse(r.findings)
    def test_scope(self):
        r = self.scan(RedirectCapture('https://other.test/', 302, response_headers={'Location':'https://outside.test'}))
        self.assertEqual(r.skipped_out_of_scope, 1)
    def test_missing_callback(self):
        with self.assertRaises(TypeError): self.a.analyze([] , scope_check=None)
    def test_invalid_limits(self):
        with self.assertRaises(ValueError): OpenRedirectAuditor(max_findings=0)
    def test_no_raw_destination_in_json(self):
        r = self.scan(RedirectCapture(BASE+'?next=https://outside.test/?token=SECRET', 200))
        s = r.to_json()
        self.assertNotIn('SECRET', s)
        self.assertNotIn('outside.test', s)
    def test_dedup(self):
        c = RedirectCapture(BASE, 302, response_headers={'Location':'https://outside.test'})
        self.assertEqual(len(self.scan(c,c).findings), 1)
    def test_max_findings(self):
        a = OpenRedirectAuditor(max_findings=1)
        r = a.analyze([RedirectCapture(BASE+'?next=https://outside.test', 302, response_headers={'Location':'https://another.test'})], scope_check=SCOPE)
        self.assertTrue(r.truncated)
        self.assertEqual(len(r.findings), 1)
    def test_max_captures(self):
        a = OpenRedirectAuditor(max_captures=1)
        r = a.analyze([RedirectCapture(BASE, 200), RedirectCapture(BASE, 200)], scope_check=SCOPE)
        self.assertTrue(r.truncated)
    def test_json_valid(self):
        self.assertIn('findings', json.loads(self.scan(RedirectCapture(BASE, 200)).to_json()))
    def test_non_http_scheme(self):
        target, _ = _destination('javascript:alert(1)', BASE)
        self.assertIsNone(target)
    def test_invalid_host(self):
        self.assertIsNone(_host('https://[broken'))
    def test_not_redirect_status(self):
        self.assertFalse(self.scan(RedirectCapture(BASE, 200, response_headers={'Location':'https://outside.test'})).findings)
    def test_ip_literal(self):
        r = self.scan(RedirectCapture(BASE, 302, response_headers={'Location':'https://127.0.0.1/'}))
        self.assertIn('ip_literal', r.findings[0].evidence)
    def test_large_body_skipped(self):
        a = OpenRedirectAuditor(max_body_chars=5)
        r = a.analyze([RedirectCapture(BASE, 200, response_body='window.location="https://outside.test"')], scope_check=SCOPE)
        self.assertFalse(r.findings)

if __name__ == '__main__': unittest.main()

