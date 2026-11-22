import unittest
from core.http_models import Header, Headers, HTTPResponse
from core.response_comparator import ResponseComparator, ComparisonError


def response(status=200, body=b'ok', content_type='text/plain', extra=()):
    headers = (Header('Content-Type', content_type),) + tuple(Header(k, v) for k, v in extra)
    return HTTPResponse(status_code=status, headers=Headers(headers), body=body)


class ComparatorTests(unittest.TestCase):
    def setUp(self):
        self.c = ResponseComparator()

    def test_equal(self):
        result = self.c.compare(response(), response())
        self.assertFalse(result.signals)
        self.assertEqual(result.text_similarity, 1)

    def test_status(self):
        self.assertTrue(self.c.compare(response(), response(403)).status_changed)

    def test_body(self):
        self.assertTrue(self.c.compare(response(), response(body=b'no')).body_changed)

    def test_size_delta(self):
        self.assertEqual(self.c.compare(response(), response(body=b'long')).body_size_delta, 2)

    def test_content_type(self):
        self.assertTrue(self.c.compare(response(), response(content_type='application/octet-stream')).content_type_changed)

    def test_json_value_only(self):
        a = response(body=b'{"a":1}', content_type='application/json')
        b = response(body=b'{"a":2}', content_type='application/json')
        r = self.c.compare(a, b)
        self.assertTrue(r.body_changed)
        self.assertFalse(r.json_structure_changed)

    def test_json_structure(self):
        a = response(body=b'{"a":1}', content_type='application/json')
        b = response(body=b'{"b":1}', content_type='application/json')
        r = self.c.compare(a, b)
        self.assertTrue(r.json_structure_changed)
        self.assertEqual(r.json_paths_added, ('/b',))

    def test_json_duplicate_rejected(self):
        with self.assertRaises(ComparisonError):
            self.c.extract(response(body=b'{"a":1,"a":2}', content_type='application/json'))

    def test_invalid_json(self):
        self.assertEqual(self.c.extract(response(body=b'{', content_type='application/json')).kind, 'invalid_json')

    def test_json_pointer_escape(self):
        x = self.c.extract(response(body=b'{"a/b": {"~":true}}', content_type='application/json'))
        self.assertIn('/a~1b/~0', x.json_paths)

    def test_header_fingerprints(self):
        a = response(extra=(('Location', '/secret?token=abc'),))
        b = response(extra=(('Location', '/secret?token=xyz'),))
        r = self.c.compare(a, b)
        self.assertIn('location', r.selected_headers_changed)
        self.assertNotIn('abc', repr(r))
        self.assertNotIn('xyz', repr(r))

    def test_volatile_headers_not_compared(self):
        a = response(extra=(('Date', 'Mon, 01 Jan 2024 00:00:00 GMT'),))
        b = response(extra=(('Date', 'Tue, 02 Jan 2024 00:00:00 GMT'),))
        self.assertEqual(self.c.compare(a, b).selected_headers_changed, ())

    def test_oversized_body_rejected(self):
        with self.assertRaises(ComparisonError):
            self.c.extract(response(body=b'x' * (2 * 1024 * 1024 + 1)))

    def test_binary_body_no_text_similarity(self):
        a = response(body=b'\x00\xff', content_type='application/octet-stream')
        self.assertIsNone(self.c.compare(a, a).text_similarity)

    def test_secret_body_not_in_repr(self):
        a = response(body=b'my-secret-token')
        self.assertNotIn('my-secret-token', repr(self.c.compare(a, a)))
        self.assertNotIn('my-secret-token', str(self.c.compare(a, a).safe_summary()))

    def test_timing_positive(self):
        r = self.c.compare_timings([100, 101, 99, 102, 98], [250, 251, 249, 252, 248])
        self.assertTrue(r.exceeds_noise_floor)

    def test_timing_jitter(self):
        r = self.c.compare_timings([100, 150, 200, 250, 300], [110, 160, 210, 260, 310])
        self.assertFalse(r.exceeds_noise_floor)

    def test_timing_bad_samples(self):
        with self.assertRaises(ComparisonError):
            self.c.compare_timings([1, 2, 3, 4, float('nan')], [1, 2, 3, 4, 5])

    def test_timing_too_few(self):
        with self.assertRaises(ComparisonError):
            self.c.compare_timings([1], [2])

    def test_no_vulnerability_claim(self):
        r = self.c.compare(response(), response(500))
        self.assertIn('not_vulnerability_confirmation', r.safe_summary()['interpretation'])


if __name__ == '__main__':
    unittest.main()

