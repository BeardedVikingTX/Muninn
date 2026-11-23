import json
import unittest
from audit.api_security import APIExchange, APISecurityAuditor, fingerprint_exchange

BASE = 'https://example.test/api/v1/users'


def ex(**kw):
    d = dict(method='GET', url=BASE, response_status=200,
             response_headers={'Content-Type': 'application/json'})
    d.update(kw)
    return APIExchange(**d)


class TestAPISecurity(unittest.TestCase):
    def setUp(self):
        self.a = APISecurityAuditor()
        self.scope = lambda url: __import__('urllib.parse', fromlist=['urlsplit']).urlsplit(url).hostname == 'example.test'

    def audit(self, *items):
        return self.a.analyze(items, scope_check=self.scope)

    def rules(self, *items):
        return {o.rule_id for o in self.audit(*items).observations}

    def test_scope_required(self):
        with self.assertRaises(ValueError): self.a.analyze([ex()])

    def test_scope_rejected(self):
        self.assertEqual(self.audit(ex(url='https://other.test/api')).api_exchanges, 0)

    def test_empty(self):
        self.assertEqual(self.audit().safe_summary()['observation_count'], 0)

    def test_non_api_ignored(self):
        self.assertEqual(self.audit(ex(url='https://example.test/home', response_headers={})).api_exchanges, 0)

    def test_api_path(self):
        self.assertEqual(self.audit(ex(response_headers={})).api_exchanges, 1)

    def test_api_accept(self):
        self.assertEqual(self.audit(ex(url='https://example.test/custom', response_headers={}, request_headers={'Accept':'application/json'})).api_exchanges, 1)

    def test_sensitive_query(self):
        self.assertIn('API-QUERY-SECRET', self.rules(ex(url=BASE+'?token=supersecret')))

    def test_query_value_redacted(self):
        self.assertNotIn('supersecret', self.audit(ex(url=BASE+'?token=supersecret')).to_json())

    def test_url_userinfo_redacted(self):
        self.assertNotIn('uniquepass987', self.audit(ex(url='https://user:uniquepass987@example.test/api?token=hidden')).to_json())

    def test_wildcard_credentials(self):
        self.assertIn('API-CORS-WILDCARD-CREDENTIALS', self.rules(ex(response_headers={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Credentials':'true'})))

    def test_wildcard_authorized(self):
        self.assertIn('API-CORS-WILDCARD-AUTH', self.rules(ex(request_headers={'Authorization':'Bearer secret'}, response_headers={'Access-Control-Allow-Origin':'*'})))

    def test_reflected_origin_review(self):
        self.assertIn('API-CORS-REFLECTION-REVIEW', self.rules(ex(request_headers={'Origin':'https://client.test'}, response_headers={'Access-Control-Allow-Origin':'https://client.test','Access-Control-Allow-Credentials':'true'})))

    def test_no_reflection_without_origin(self):
        self.assertNotIn('API-CORS-REFLECTION-REVIEW', self.rules(ex(response_headers={'Access-Control-Allow-Origin':'https://client.test','Access-Control-Allow-Credentials':'true'})))

    def test_authenticated_cache(self):
        self.assertIn('API-AUTH-CACHE-REVIEW', self.rules(ex(request_headers={'Authorization':'Bearer abc'})))

    def test_private_cache(self):
        self.assertNotIn('API-AUTH-CACHE-REVIEW', self.rules(ex(request_headers={'Authorization':'Bearer abc'}, response_headers={'Cache-Control':'private'})))

    def test_http_auth(self):
        self.assertIn('API-AUTH-HTTP', self.rules(ex(url='http://example.test/api', request_headers={'Cookie':'session=abc'})))

    def test_no_http_auth_without_credentials(self):
        self.assertNotIn('API-AUTH-HTTP', self.rules(ex(url='http://example.test/api')))

    def test_expose_wildcard(self):
        self.assertIn('API-CORS-EXPOSE-WILDCARD', self.rules(ex(response_headers={'Access-Control-Expose-Headers':'*','Access-Control-Allow-Credentials':'true'})))

    def test_trace(self):
        self.assertIn('API-TRACE-ADVERTISED', self.rules(ex(method='OPTIONS', response_headers={'Allow':'GET, TRACE, OPTIONS'})))

    def test_verbose_error(self):
        self.assertIn('API-VERBOSE-ERROR', self.rules(ex(response_status=500, response_body='Traceback (most recent call last):\nsecret=password')))

    def test_verbose_error_redacted(self):
        self.assertNotIn('password', self.audit(ex(response_status=500, response_body='Traceback (most recent call last):\npassword')).to_json())

    def test_graphql_introspection(self):
        self.assertIn('API-GRAPHQL-INTROSPECTION-REVIEW', self.rules(ex(url='https://example.test/graphql', response_body='{"data":{"__schema":{}}}')))

    def test_cookie_secure(self):
        self.assertIn('API-COOKIE-SECURE-REVIEW', self.rules(ex(response_headers={'Set-Cookie':'session=secret; HttpOnly'})))

    def test_cookie_secure_present(self):
        self.assertNotIn('API-COOKIE-SECURE-REVIEW', self.rules(ex(response_headers={'Set-Cookie':'session=secret; Secure; HttpOnly'})))

    def test_bounded_exchanges(self):
        a = APISecurityAuditor(max_exchanges=1)
        r = a.analyze([ex(), ex()], scope_check=self.scope)
        self.assertTrue(r.truncated)
        self.assertEqual(r.exchanges_seen, 1)

    def test_bounded_observations(self):
        a = APISecurityAuditor(max_observations=1)
        r = a.analyze([ex(url=BASE+'?token=x', request_headers={'Authorization':'abc'})], scope_check=self.scope)
        self.assertTrue(r.truncated)
        self.assertEqual(len(r.observations), 1)

    def test_invalid_limits(self):
        with self.assertRaises(ValueError): APISecurityAuditor(max_body_bytes=0)

    def test_deterministic_json(self):
        x = ex(url=BASE+'?token=abc')
        self.assertEqual(self.audit(x).to_json(), self.audit(x).to_json())
        self.assertEqual(json.loads(self.audit(x).to_json())['api_exchanges'], 1)

    def test_fingerprint_stable_and_safe(self):
        self.assertEqual(fingerprint_exchange(ex(url=BASE+'?token=abc')), fingerprint_exchange(ex(url=BASE+'?token=xyz')))

    def test_binary_body(self):
        self.assertIn('API-VERBOSE-ERROR', self.rules(ex(response_status=500, response_body=b'Traceback (most recent call last):')))

    def test_header_lists(self):
        self.assertIn('API-TRACE-ADVERTISED', self.rules(ex(method='OPTIONS', response_headers={'Allow':['GET','TRACE']})))


if __name__ == '__main__': unittest.main()

