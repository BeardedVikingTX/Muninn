import json
import unittest
from audit.ssrf import SSRFAuditor, SSRFObservation, OASTEvent, SSRFPolicy, classify_destination

BASE = 'https://example.test/fetch'

def obs(**kw):
    data = dict(url=BASE, parameter='url', candidate_url='https://public.example/resource')
    data.update(kw)
    return SSRFObservation(**data)

def run(items, events=(), policy=None, scope=None):
    return SSRFAuditor(policy).analyze(items, scope_check=scope or (lambda u: u.startswith('https://example.test/')), oast_events=events)

class SSRFTests(unittest.TestCase):
    def codes(self, report):
        return {f.code for f in report.findings}

    def test_url_like_parameter(self):
        self.assertIn('url_fetch_input', self.codes(run([obs()])))

    def test_non_url_parameter(self):
        self.assertNotIn('url_fetch_input', self.codes(run([obs(parameter='name')])))

    def test_suffix_parameter(self):
        self.assertIn('url_fetch_input', self.codes(run([obs(parameter='avatar_url')])))

    def test_loopback(self):
        self.assertIn('ip_loopback', classify_destination('http://127.0.0.1/a'))

    def test_ipv6_loopback(self):
        self.assertIn('ip_loopback', classify_destination('http://[::1]/'))

    def test_private(self):
        self.assertIn('ip_private', classify_destination('http://10.0.0.2/'))

    def test_linklocal(self):
        self.assertIn('ip_link_local', classify_destination('http://169.254.1.2/'))

    def test_metadata(self):
        self.assertIn('metadata_destination', classify_destination('http://169.254.169.254/'))

    def test_metadata_dns(self):
        self.assertIn('metadata_destination', classify_destination('http://metadata.google.internal/'))

    def test_localhost(self):
        self.assertIn('loopback_hostname', classify_destination('http://localhost/'))

    def test_internal_hint(self):
        self.assertIn('internal_hostname_hint', classify_destination('http://backend.internal/'))

    def test_non_http(self):
        self.assertIn('non_http_scheme', classify_destination('file:///etc/example'))

    def test_scheme_relative(self):
        self.assertIn('scheme_relative', classify_destination('//example.com/'))

    def test_userinfo(self):
        self.assertIn('userinfo', classify_destination('https://user@example.com/'))

    def test_double_encoded(self):
        self.assertIn('ip_loopback', classify_destination('http%253A%252F%252F127.0.0.1%252F'))

    def test_invalid_port(self):
        self.assertIn('malformed_url', classify_destination('http://example.com:abc/'))

    def test_invalid_ipv6(self):
        self.assertIn('malformed_url', classify_destination('http://[bad/'))

    def test_public_ip_not_risky(self):
        self.assertNotIn('destination_review', self.codes(run([obs(candidate_url='https://8.8.8.8/')])) )

    def test_out_of_scope(self):
        r = run([obs(url='https://outside.test/fetch')])
        self.assertEqual((r.analyzed, r.skipped_out_of_scope), (0, 1))

    def test_invalid_target(self):
        self.assertEqual(run([obs(url='javascript:alert(1)')]).skipped_invalid, 1)

    def test_scope_callback_required(self):
        with self.assertRaises(TypeError):
            SSRFAuditor().analyze([obs()], scope_check=None)

    def test_scope_exception_fails_closed(self):
        with self.assertRaises(RuntimeError):
            run([obs()], scope=lambda u: (_ for _ in ()).throw(RuntimeError('fail')))

    def test_untrusted_oast_not_accepted(self):
        r = run([obs(correlation_id='x')], [OASTEvent('x', 'http', trusted=False, source_attributed=True)])
        self.assertNotIn('oast_http_callback', self.codes(r))

    def test_unattributed_oast_not_accepted(self):
        r = run([obs(correlation_id='x')], [OASTEvent('x', 'http', trusted=True)])
        self.assertNotIn('oast_http_callback', self.codes(r))

    def test_mismatched_oast(self):
        r = run(
            [obs(correlation_id="expected")],
            [
                OASTEvent(
                    "different",
                    "http",
                    trusted=True,
                    source_attributed=True,
                )
            ],
        )
        self.assertNotIn("oast_http_callback", self.codes(r))

