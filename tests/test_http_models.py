import unittest
from dataclasses import FrozenInstanceError
from core.http_models import (
    Header, Headers, HTTPModelError, HTTPRequest, HTTPResponse, HTTPTransaction,
    parse_http1_request, parse_http1_response,
)

class HTTPModelsTests(unittest.TestCase):
    def test_request_roundtrip_duplicate_headers(self):
        raw = b'GET /a?x=1&x=2&blank= HTTP/1.1\r\nHost: example.org\r\nX-Test: one\r\nX-Test: two\r\n\r\n'
        r = parse_http1_request(raw)
        self.assertEqual(r.raw, raw)
        self.assertEqual(r.headers.get_all('x-test'), ('one', 'two'))
        self.assertEqual([(p.name, p.value) for p in r.query_parameters], [('x','1'), ('x','2'), ('blank','')])
        self.assertNotIn('/a?', repr(r))

    def test_binary_body_preserved(self):
        raw = b'POST / HTTP/1.1\r\nHost: e.org\r\n\r\n\x00\xff\r\n'
        self.assertEqual(parse_http1_request(raw).body, b'\x00\xff\r\n')

    def test_response_no_reason(self):
        r = parse_http1_response(b'HTTP/1.1 204\r\nX-Id: 1\r\n\r\n')
        self.assertEqual((r.status_code, r.reason), (204, ''))

    def test_lf_only(self):
        r = parse_http1_response(b'HTTP/1.0 200 OK\nX-A: b\n\nhello')
        self.assertEqual(r.body, b'hello')

    def test_malformed_rejected(self):
        for raw in (b'GET / HTTP/1.1\r\nX: y', b'GET / HTTP/1.1\r\n Folded: x\r\n\r\n',
                    b'GET / HTTP/1.1\r\nBad Name: x\r\n\r\n'):
            with self.subTest(raw=raw), self.assertRaises(HTTPModelError):
                parse_http1_request(raw)

    def test_crlf_injection_rejected(self):
        with self.assertRaises(HTTPModelError):
            Header('X', 'foo\r\nInjected: yes')

    def test_safe_summary_omits_secrets(self):
        raw = b'GET /?token=private HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\n'
        r = parse_http1_request(raw)
        s = str(r.safe_summary()) + repr(r)
        self.assertNotIn('private', s)
        self.assertNotIn('secret', s)

    def test_source_url_rejects_credentials(self):
        with self.assertRaises(HTTPModelError):
            HTTPRequest('GET', '/', source_url='https://alice:password@example.com/')

    def test_transaction_optional_response(self):
        tx = HTTPTransaction('burp-123', HTTPRequest('GET', '/'))
        self.assertIsNone(tx.response)
        self.assertEqual(tx.safe_summary()['source_id'], 'burp-123')

    def test_immutable(self):
        r = HTTPRequest('GET', '/')
        with self.assertRaises(FrozenInstanceError):
            r.method = 'POST'

    def test_http2_semantic_model(self):
        r = HTTPRequest('GET', '/resource', version='HTTP/2')
        self.assertEqual(r.version, 'HTTP/2')

    def test_bad_response_status(self):
        with self.assertRaises(HTTPModelError):
            parse_http1_response(b'HTTP/1.1 20X Bad\r\n\r\n')

    def test_empty_duplicate_header(self):
        h = Headers((Header('X-Test', ''), Header('x-test', 'b')))
        self.assertEqual(h.get('X-TEST'), '')
        self.assertEqual(len(h), 2)

if __name__ == '__main__':
    unittest.main()

