import json
import unittest
from audit.auth_bypass import AuthBypassAuditor, AuthExchange

URL = 'https://example.test/api/private?token=never-include-me'


def sample(state, status=200, body='{"id":1,"name":"Alice"}', **kwargs):
    return AuthExchange('GET', URL, state, status,
                        {'Content-Type': 'application/json'}, body, **kwargs)


class AuthBypassTests(unittest.TestCase):
    def setUp(self):
        self.auditor = AuthBypassAuditor()
        self.scope = lambda url: url.startswith('https://example.test/')

    def analyze(self, records):
        return self.auditor.analyze(records, scope_check=self.scope)

    def test_equal_successful_shapes_flagged(self):
        report = self.analyze([sample('authenticated'), sample('anonymous')])
        self.assertEqual(len(report.observations), 1)
        self.assertEqual(report.observations[0].confidence, 'low')

    def test_denied_unauth_not_flagged(self):
        self.assertFalse(self.analyze([sample('authenticated'), sample('anonymous', 401)]).observations)

    def test_no_baseline_no_finding(self):
        self.assertFalse(self.analyze([sample('anonymous')]).observations)

    def test_no_unauth_no_finding(self):
        self.assertFalse(self.analyze([sample('authenticated')]).observations)

    def test_invalid_and_expired(self):
        report = self.analyze([sample('authenticated'), sample('invalid'), sample('expired')])
        self.assertEqual(len(report.observations), 2)

    def test_json_values_not_retained(self):
        report = self.analyze([sample('authenticated'), sample('anonymous', body='{"id":99,"name":"Bob"}')])
        self.assertEqual(len(report.observations), 1)
        self.assertNotIn('Alice', report.to_json())
        self.assertNotIn('Bob', report.to_json())
        self.assertNotIn('never-include-me', report.to_json())

    def test_different_json_shapes(self):
        self.assertFalse(self.analyze([sample('authenticated'), sample('anonymous', body='{"error":"no"}')]).observations)

    def test_scope_exclusion(self):
        report = self.auditor.analyze([sample('authenticated')], scope_check=lambda _: False)
        self.assertEqual((report.inspected, report.excluded), (0, 1))

    def test_missing_scope_callback(self):
        with self.assertRaises(TypeError):
            self.auditor.analyze([sample('authenticated')], scope_check=None)

    def test_status_validation(self):
        with self.assertRaises(ValueError):
            sample('anonymous', status=999)

    def test_state_validation(self):
        with self.assertRaises(ValueError):
            sample('unknown')

    def test_invalid_url(self):
        with self.assertRaises(ValueError):
            AuthExchange('GET', 'not-a-url', 'anonymous', 200)

    def test_nonprotected_ignored(self):
        self.assertFalse(self.analyze([sample('authenticated'), sample('anonymous', expected_protected=False)]).observations)

    def test_scenario_separation(self):
        self.assertFalse(self.analyze([sample('authenticated', scenario='one'), sample('anonymous', scenario='two')]).observations)

    def test_method_separation(self):
        other = AuthExchange('POST', URL, 'anonymous', 200, {'Content-Type':'application/json'}, '{}')
        self.assertFalse(self.analyze([sample('authenticated'), other]).observations)

    def test_bounded_input(self):
        report = AuthBypassAuditor(max_exchanges=1).analyze([sample('authenticated'), sample('anonymous')], scope_check=self.scope)
        self.assertTrue(report.truncated)
        self.assertEqual(report.inspected, 1)

    def test_bounded_observations(self):
        report = AuthBypassAuditor(max_observations=1).analyze([sample('authenticated'), sample('anonymous'), sample('invalid')], scope_check=self.scope)
        self.assertTrue(report.truncated)
        self.assertEqual(len(report.observations), 1)

    def test_invalid_limits(self):
        with self.assertRaises(ValueError):
            AuthBypassAuditor(max_body_bytes=0)

    def test_invalid_similarity(self):
        with self.assertRaises(ValueError):
            AuthBypassAuditor(min_similarity=1.1)

    def test_deterministic_json(self):
        records = [sample('authenticated'), sample('anonymous')]
        self.assertEqual(self.analyze(records).to_json(), self.analyze(records).to_json())

    def test_no_raw_request_ids(self):
        report = self.analyze([sample('authenticated', request_id='secret1'), sample('anonymous', request_id='secret2')])
        self.assertNotIn('secret1', report.to_json())
        self.assertNotIn('secret2', report.to_json())

    def test_query_excluded(self):
        self.assertNotIn('token=', self.analyze([sample('authenticated'), sample('anonymous')]).to_json())

    def test_json_serializable(self):
        self.assertEqual(len(json.loads(self.analyze([sample('authenticated'), sample('anonymous')]).to_json())['observations']), 1)

    def test_html_matching(self):
        a = sample('authenticated', body='<html>same</html>')
        b = sample('anonymous', body='<html>same</html>')
        self.assertEqual(len(self.analyze([a,b]).observations), 1)

    def test_html_different(self):
        a = sample('authenticated', body='<html>private</html>')
        b = sample('anonymous', body='<html>login</html>')
        self.assertFalse(self.analyze([a,b]).observations)

    def test_unprotected_controls_ignored(self):
        self.assertFalse(self.analyze([sample('authenticated', expected_protected=False), sample('anonymous')]).observations)


if __name__ == '__main__':
    unittest.main()

