import unittest
from core.http_models import HTTPRequest, HTTPTransaction, Headers, Header
from core.injection_points import InjectionPointDiscovery, InjectionPointError


def request(target='/', body=b'', content_type=None, extra=()):
    headers = list(extra)
    if content_type:
        headers.append(Header('Content-Type', content_type))
    return HTTPRequest('POST', target, headers=Headers(tuple(headers)), body=body)


class InjectionPointTests(unittest.TestCase):
    def setUp(self):
        self.d = InjectionPointDiscovery()

    def test_query_duplicates_and_blanks(self):
        p = [x for x in self.d.discover(request('/?id=1&id=2&empty=')) if x.location == 'query']
        self.assertEqual([(x.name, x.occurrence) for x in p], [('id', 0), ('id', 1), ('empty', 0)])

    def test_path_segments(self):
        p = [x for x in self.d.discover(request('/users/123')) if x.location == 'path']
        self.assertEqual([x.pointer for x in p], ['/1', '/2'])

    def test_form(self):
        p = self.d.discover(request('/', b'a=1&a=2', 'application/x-www-form-urlencoded'))
        self.assertEqual([x.occurrence for x in p if x.location == 'form'], [0, 1])

    def test_nested_json(self):
        p = self.d.discover(request('/', b'{"user":{"name":"a","roles":["x",true,null]}}', 'application/json'))
        self.assertEqual([x.pointer for x in p if x.location == 'json'],
                         ['/user/name', '/user/roles/0', '/user/roles/1', '/user/roles/2'])

    def test_json_escaping(self):
        p = self.d.discover(request('/', b'{"a/b~c":1}', 'application/json'))
        self.assertEqual([x.pointer for x in p if x.location == 'json'], ['/a~1b~0c'])

    def test_sensitive_names(self):
        p = self.d.discover(request('/?access_token=secret'))
        self.assertTrue(next(x for x in p if x.location == 'query').sensitive)
        self.assertNotIn('secret', repr(p))

    def test_sensitive_nested_json(self):
        p = self.d.discover(request('/', b'{"auth":{"value":"supersecret"}}', 'application/json'))
        self.assertTrue(next(x for x in p if x.location == 'json').sensitive)
        self.assertNotIn('supersecret', repr(p))

    def test_header_allowlist(self):
        p = self.d.discover(request('/', extra=(Header('Authorization', 'Bearer secret'), Header('Origin', 'https://example.org'))))
        self.assertEqual([x.name for x in p if x.location == 'header'], ['Origin'])

    def test_cookies_are_sensitive(self):
        p = self.d.discover(request('/', extra=(Header('Cookie', 'sid=abc; theme=dark'),)))
        self.assertEqual(len([x for x in p if x.location == 'cookie']), 2)
        self.assertTrue(all(x.sensitive for x in p if x.location == 'cookie'))

    def test_no_active_permission(self):
        self.assertTrue(all(not x.active_testing_allowed for x in self.d.discover(request('/?a=1'))))

    def test_stable_identifiers(self):
        r = request('/?a=one&a=two')
        self.assertEqual(self.d.discover(r), self.d.discover(r))
        self.assertNotEqual(self.d.discover(r)[0].id, self.d.discover(r)[1].id)

    def test_transaction(self):
        tx = HTTPTransaction('burp-1', request('/?x=1'))
        self.assertEqual(self.d.discover(tx), self.d.discover(tx.request))

    def test_binary_body_ignored(self):
        self.assertEqual(self.d.discover(request('/', b'\x00\xff')), ())

    def test_invalid_json_ignored(self):
        self.assertEqual(self.d.discover(request('/', b'{broken', 'application/json')), ())

    def test_body_limit(self):
        with self.assertRaises(InjectionPointError):
            InjectionPointDiscovery(max_body=2).discover(request('/', b'abc'))

    def test_point_limit(self):
        with self.assertRaises(InjectionPointError):
            InjectionPointDiscovery(max_points=1).discover(request('/?a=1&b=2'))

    def test_query_limit(self):
        with self.assertRaises(InjectionPointError):
            self.d.discover(request('/?' + '&'.join('a=1' for _ in range(1025))))

    def test_safe_summary_omits_names(self):
        p = self.d.discover(request('/?secret_parameter=secret'))[0]
        self.assertNotIn('secret', str(p.safe_summary()))

    def test_type_validation(self):
        with self.assertRaises(TypeError):
            self.d.discover(object())


if __name__ == '__main__':
    unittest.main()

