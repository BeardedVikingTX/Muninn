import json
import unittest
from audit.cache_poisoning import CacheCapture, CachePoisoningAuditor

URL = 'https://example.test/page?secret=never-report'
KEY = 'example.test/page'
MARK = 'muninn-test-123'


def capture(phase, *, body='', headers=None, marker='', key=KEY, scenario='a', url=URL, status=200):
    return CacheCapture(scenario, phase, 'GET', url, status,
                        response_headers=headers or {'Cache-Control': 'public, max-age=60'},
                        response_body=body, cache_key=key, marker=marker)


def run(items, **kw):
    return CachePoisoningAuditor(**kw).analyze(items, scope_check=lambda u: u.startswith('https://example.test/'))


class CacheTests(unittest.TestCase):
    def test_reflection(self):
        r = run([capture('baseline'), capture('candidate', body=MARK, marker=MARK)])
        self.assertEqual(r.findings[0].code, 'CACHEABLE_MARKER_REFLECTION')

    def test_propagation(self):
        r = run([capture('baseline'), capture('candidate', body=MARK, marker=MARK),
                 capture('followup', body=MARK, headers={'X-Cache': 'HIT'})])
        self.assertEqual(r.findings[0].code, 'CACHED_MARKER_PROPAGATION')

    def test_no_baseline(self):
        self.assertFalse(run([capture('candidate', body=MARK, marker=MARK)]).findings)

    def test_no_candidate(self):
        self.assertFalse(run([capture('baseline')]).findings)

    def test_no_marker(self):
        self.assertFalse(run([capture('baseline'), capture('candidate', body=MARK)]).findings)

    def test_unreflected(self):
        self.assertFalse(run([capture('baseline'), capture('candidate', marker=MARK)]).findings)

    def test_existing_marker(self):
        self.assertFalse(run([capture('baseline', body=MARK), capture('candidate', body=MARK, marker=MARK)]).findings)

    def test_no_store(self):
        self.assertFalse(run([capture('baseline'), capture('candidate', body=MARK, marker=MARK,
                                      headers={'Cache-Control': 'no-store'})]).findings)

    def test_private(self):
        self.assertFalse(run([capture('baseline'), capture('candidate', body=MARK, marker=MARK,
                                      headers={'Cache-Control': 'private, max-age=60'})]).findings)

    def test_not_cacheable(self):
        self.assertFalse(run([capture('baseline'), capture('candidate', body=MARK, marker=MARK,
                                      headers={'Content-Type': 'text/html'})]).findings)

    def test_wrong_status(self):
        self.assertFalse(run([capture('baseline'), capture('candidate', body=MARK, marker=MARK, status=500)]).findings)

    def test_key_mismatch(self):
        self.assertFalse(run([capture('baseline'), capture('candidate', body=MARK, marker=MARK, key='different')]).findings)

    def test_origin_mismatch(self):
        self.assertFalse(run([capture('baseline'), capture('candidate', body=MARK, marker=MARK,
                                      url='https://other.test/page')]).findings)

    def test_scope_exclusion(self):
        r = run([capture('baseline', url='https://outside.test/'), capture('candidate', body=MARK, marker=MARK)])
        self.assertEqual(r.excluded, 1)
        self.assertFalse(r.findings)

    def test_scope_exception(self):
        r = CachePoisoningAuditor().analyze([capture('baseline')], scope_check=lambda u: 1/0)
        self.assertEqual(r.excluded, 1)

    def test_missing_scope(self):
        with self.assertRaises(TypeError):
            CachePoisoningAuditor().analyze([], scope_check=None)

    def test_invalid_phase(self):
        with self.assertRaises(ValueError):
            capture('unknown')

    def test_invalid_url(self):
        with self.assertRaises(ValueError):
            capture('baseline', url='file:///etc/passwd')

    def test_invalid_marker(self):
        with self.assertRaises(ValueError):
            capture('candidate', marker='a b')

    def test_limits(self):
        with self.assertRaises(ValueError):
            CachePoisoningAuditor(max_findings=0)

    def test_capture_limit(self):
        r = run([capture('baseline'), capture('candidate', body=MARK, marker=MARK)], max_captures=1)
        self.assertTrue(r.truncated)
        self.assertFalse(r.findings)

    def test_finding_limit(self):
        items = [capture('baseline', scenario=s) for s in ('a', 'b')]
        items += [capture('candidate', scenario=s, body=MARK, marker=MARK) for s in ('a', 'b')]
        r = run(items, max_findings=1)
        self.assertEqual(len(r.findings), 1)
        self.assertTrue(r.truncated)

    def test_json_redaction(self):
        r = run([capture('baseline'), capture('candidate', body=MARK, marker=MARK)])
        encoded = r.to_json()
        self.assertNotIn('never-report', encoded)
        self.assertNotIn(MARK, encoded)
        self.assertIn('findings', json.loads(encoded))

    def test_deterministic(self):
        items = [capture('baseline'), capture('candidate', body=MARK, marker=MARK)]
        self.assertEqual(run(items).to_json(), run(items).to_json())

    def test_no_followup_hit(self):
        r = run([capture('baseline'), capture('candidate', body=MARK, marker=MARK),
                 capture('followup', body=MARK, headers={'X-Cache': 'MISS'})])
        self.assertEqual(r.findings[0].code, 'CACHEABLE_MARKER_REFLECTION')

    def test_followup_with_own_marker_not_propagation(self):
        r = run([capture('baseline'), capture('candidate', body=MARK, marker=MARK),
                 capture('followup', body=MARK, marker=MARK, headers={'X-Cache': 'HIT'})])
        self.assertEqual(r.findings[0].code, 'CACHEABLE_MARKER_REFLECTION')


if __name__ == '__main__':
    unittest.main()

