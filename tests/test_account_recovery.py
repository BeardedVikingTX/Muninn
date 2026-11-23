import json
import unittest
from core.http_models import HTTPRequest, HTTPResponse, HTTPTransaction, Headers, Header
from audit.account_recovery import AccountRecoveryAuditor, RecoveryAuditError, analyze_account_recovery


def hs(**kwargs):
    return Headers(tuple(Header(k.replace('_', '-'), v) for k, v in kwargs.items()))


def tx(i='t1', path='/forgot-password', method='POST', status=200, body=b'OK',
       response_headers=None, request_headers=None, source_url=None):
    req = HTTPRequest(method, path, headers=request_headers or hs(Host='example.org'), body=b'email=secret@example.com', source_url=source_url)
    resp = None if status is None else HTTPResponse(status, headers=response_headers or Headers(), body=body)
    return HTTPTransaction(i, req, resp)


class AccountRecoveryTests(unittest.TestCase):
    def codes(self, report):
        return {o.code for o in report.observations}

    def test_empty(self):
        self.assertEqual(analyze_account_recovery([]).safe_summary()['analyzed'], 0)

    def test_non_recovery_skipped(self):
        r = analyze_account_recovery([tx(path='/api/products')])
        self.assertEqual((r.recovery_candidates, r.skipped), (0, 1))

    def test_recovery_identified(self):
        self.assertEqual(analyze_account_recovery([tx()]).recovery_candidates, 1)

    def test_missing_response(self):
        self.assertIn('MISSING_RESPONSE', self.codes(analyze_account_recovery([tx(status=None)])))

    def test_cache_policy(self):
        self.assertIn('CACHE_POLICY_REVIEW', self.codes(analyze_account_recovery([tx()])))

    def test_private_cache(self):
        r = analyze_account_recovery([tx(response_headers=hs(Cache_Control='private', Referrer_Policy='no-referrer'))])
        self.assertNotIn('CACHE_POLICY_REVIEW', self.codes(r))

    def test_no_store(self):
        r = analyze_account_recovery([tx(response_headers=hs(Cache_Control='no-store', Referrer_Policy='no-referrer'))])
        self.assertNotIn('CACHE_POLICY_REVIEW', self.codes(r))

    def test_referrer_policy(self):
        self.assertIn('REFERRER_POLICY_REVIEW', self.codes(analyze_account_recovery([tx()])))

    def test_cookie_flags(self):
        r = analyze_account_recovery([tx(response_headers=hs(Set_Cookie='session=verysecret; Path=/'))])
        self.assertIn('COOKIE_FLAGS_REVIEW', self.codes(r))
        self.assertNotIn('verysecret', json.dumps([o.safe_summary() for o in r.observations]))

    def test_secure_cookie(self):
        r = analyze_account_recovery([tx(response_headers=hs(Set_Cookie='session=secret; Secure; HttpOnly; SameSite=Lax'))])
        self.assertNotIn('COOKIE_FLAGS_REVIEW', self.codes(r))

    def test_body_field_label(self):
        r = analyze_account_recovery([tx(body=b'{"reset_token":"dont_log_me"}', response_headers=hs(Content_Type='application/json'))])
        self.assertIn('RECOVERY_MATERIAL_IN_BODY_REVIEW', self.codes(r))
        self.assertNotIn('dont_log_me', json.dumps([o.safe_summary() for o in r.observations]))

    def test_binary_body_not_scanned(self):
        r = analyze_account_recovery([tx(body=b'reset_token', response_headers=hs(Content_Type='application/octet-stream'))])
        self.assertNotIn('RECOVERY_MATERIAL_IN_BODY_REVIEW', self.codes(r))

    def test_redirect_secret_parameter(self):
        r = analyze_account_recovery([tx(status=302, response_headers=hs(Location='https://example.org/reset?token=verysecret'))])
        self.assertIn('REDIRECT_QUERY_SECRET_REVIEW', self.codes(r))
        self.assertNotIn('verysecret', json.dumps([o.safe_summary() for o in r.observations]))

    def test_cross_host_redirect(self):
        r = analyze_account_recovery([tx(status=302, source_url='https://example.org/forgot-password', response_headers=hs(Location='https://elsewhere.org/continue'))])
        self.assertIn('CROSS_HOST_REDIRECT_REVIEW', self.codes(r))

    def test_same_host_redirect(self):
        r = analyze_account_recovery([tx(status=302, source_url='https://example.org/forgot-password', response_headers=hs(Location='https://example.org/continue'))])
        self.assertNotIn('CROSS_HOST_REDIRECT_REVIEW', self.codes(r))

    def test_response_variation(self):
        r = analyze_account_recovery([tx('a', body=b'one'), tx('b', body=b'two')])
        self.assertIn('RECOVERY_RESPONSE_VARIATION', self.codes(r))

    def test_identical_responses(self):
        r = analyze_account_recovery([tx('a'), tx('b')])
        self.assertNotIn('RECOVERY_RESPONSE_VARIATION', self.codes(r))

    def test_different_endpoints(self):
        r = analyze_account_recovery([tx('a', '/forgot-password', body=b'one'), tx('b', '/reset-password', body=b'two')])
        self.assertNotIn('RECOVERY_RESPONSE_VARIATION', self.codes(r))

    def test_different_hosts(self):
        r = analyze_account_recovery([tx('a', source_url='https://a.example/forgot-password', body=b'one'), tx('b', source_url='https://b.example/forgot-password', body=b'two')])
        self.assertNotIn('RECOVERY_RESPONSE_VARIATION', self.codes(r))

    def test_no_sensitive_request_data(self):
        r = analyze_account_recovery([tx(path='/forgot-password?email=private@example.org')])
        self.assertNotIn('private@example.org', repr(r))
        self.assertNotIn('private@example.org', json.dumps(r.safe_summary()))

    def test_invalid_limits(self):
        for kwargs in ({'max_transactions': 0}, {'max_observations': -1}, {'inspect_body_bytes': 999999999}, {'max_transactions': True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(RecoveryAuditError):
                AccountRecoveryAuditor(**kwargs)

    def test_transaction_limit(self):
        with self.assertRaises(RecoveryAuditError):
            AccountRecoveryAuditor(max_transactions=1).analyze([tx('a'), tx('b')])

    def test_observation_limit(self):
        with self.assertRaises(RecoveryAuditError):
            AccountRecoveryAuditor(max_observations=1).analyze([tx()])

    def test_invalid_input(self):
        with self.assertRaises(RecoveryAuditError):
            analyze_account_recovery([object()])

    def test_determinism(self):
        data = [tx('a', body=b'one'), tx('b', body=b'two')]
        self.assertEqual(analyze_account_recovery(data), analyze_account_recovery(data))

    def test_no_network_dependency(self):
        # There is no HTTP adapter, socket or network configuration in the API.
        self.assertEqual(analyze_account_recovery([tx()]).analyzed, 1)


if __name__ == '__main__':
    unittest.main()

