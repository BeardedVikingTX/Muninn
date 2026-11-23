import unittest
from audit.path_traversal import (
    PathCandidate, TraversalCapture, TraversalConfig, PathTraversalAuditor,
    decode_layers, classify_path,
)

URL = 'https://example.test/download?file=..%2Fprivate%2Fdoc.txt'
SCOPE = lambda url: url.startswith('https://example.test/')

class PathTraversalTests(unittest.TestCase):
    def audit(self, captures, **kw):
        return PathTraversalAuditor(**kw).analyze(captures, scope_check=SCOPE)

    def test_percent_decode(self):
        self.assertEqual(decode_layers('%252e%252e%252f')[-1], '../')
    def test_decode_bounded(self):
        self.assertLessEqual(len(decode_layers('%252525252e')), 5)
    def test_decode_rounds_invalid(self):
        with self.assertRaises(ValueError): decode_layers('x', 9)
    def test_parent_unix(self):
        self.assertIn('parent_segments', classify_path('../etc/passwd'))
    def test_parent_windows(self):
        self.assertIn('parent_segments', classify_path('..\\windows\\win.ini'))
    def test_encoded(self):
        self.assertIn('encoded_path', classify_path('%2e%2e%2f'))
    def test_double_encoded(self):
        self.assertIn('multi_encoded_path', classify_path('%252e%252e%252f'))
    def test_absolute(self):
        self.assertIn('absolute_path', classify_path('/tmp/file'))
    def test_drive(self):
        self.assertIn('windows_absolute_path', classify_path('C:\\Windows\\win.ini'))
    def test_unc(self):
        self.assertIn('unc_path', classify_path('\\\\server\\share\\file'))
    def test_control(self):
        self.assertIn('control_character', classify_path('abc%00'))
    def test_safe(self):
        self.assertFalse(classify_path('reports/2026/summary.pdf'))
    def test_query_discovery(self):
        report = self.audit([TraversalCapture(URL, status=200)])
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].confidence, 'low')
    def test_no_discovery_unrelated_parameter(self):
        self.assertFalse(self.audit([TraversalCapture('https://example.test/?q=..%2F')]).findings)
    def test_explicit_candidate(self):
        cap = TraversalCapture('https://example.test/api', candidates=(PathCandidate('json', 'target', '../a'),))
        self.assertEqual(len(self.audit([cap]).findings), 1)
    def test_verified_read(self):
        cap = TraversalCapture(URL, status=200, verified_protected_content=True, fixture_id='fixture-1')
        finding = self.audit([cap]).findings[0]
        self.assertEqual((finding.confidence, finding.severity), ('high', 'high'))
    def test_verified_write(self):
        cap = TraversalCapture(URL, verified_write_outside_boundary=True, fixture_id='fixture-2')
        self.assertEqual(self.audit([cap]).findings[0].severity, 'critical')
    def test_untrusted_verified_flag(self):
        cap = TraversalCapture(URL, verified_protected_content=True)
        self.assertEqual(self.audit([cap]).findings[0].confidence, 'low')
    def test_baseline_status(self):
        cap = TraversalCapture(URL, status=200, baseline_status=403)
        self.assertEqual(self.audit([cap]).findings[0].confidence, 'medium')
    def test_no_baseline_no_confirmation(self):
        cap = TraversalCapture(URL, status=200)
        self.assertEqual(self.audit([cap]).findings[0].confidence, 'low')
    def test_scope_skip(self):
        cap = TraversalCapture('https://elsewhere.test/?file=../a')
        report = self.audit([cap])
        self.assertEqual((report.skipped_out_of_scope, len(report.findings)), (1, 0))
    def test_scope_required(self):
        with self.assertRaises(TypeError): PathTraversalAuditor().analyze([], scope_check=None)
    def test_scope_exception_fail_closed(self):
        def fail(_): raise RuntimeError('scope unavailable')
        with self.assertRaises(RuntimeError): PathTraversalAuditor().analyze([TraversalCapture(URL)], scope_check=fail)
    def test_deduplicate(self):
        cap = TraversalCapture(URL)
        self.assertEqual(len(self.audit([cap, cap]).findings), 1)
    def test_redaction(self):
        cap = TraversalCapture('https://example.test/?file=..%2FSECRET-STRING&token=private')
        report = self.audit([cap]).to_json()
        self.assertNotIn('SECRET-STRING', report)
        self.assertNotIn('private', report)
    def test_capture_limit(self):
        report = self.audit([TraversalCapture(URL)] * 3, config=TraversalConfig(max_captures=2))
        self.assertTrue(report.truncated)
        self.assertEqual(report.captures_analyzed, 2)
    def test_finding_limit(self):
        caps = [TraversalCapture(f'https://example.test/{i}?file=../a') for i in range(3)]
        report = self.audit(caps, config=TraversalConfig(max_findings=1))
        self.assertTrue(report.truncated)
        self.assertEqual(len(report.findings), 1)
    def test_value_length_limit(self):
        cap = TraversalCapture('https://example.test/', candidates=(PathCandidate('json','file','../'+'x'*100),))
        report = self.audit([cap], config=TraversalConfig(max_value_length=10))
        self.assertTrue(report.truncated)
        self.assertFalse(report.findings)
    def test_invalid_url(self):
        with self.assertRaises(ValueError): self.audit([TraversalCapture('/relative')])
    def test_invalid_status(self):
        with self.assertRaises(ValueError): self.audit([TraversalCapture(URL, status=700)])
    def test_json_deterministic(self):
        cap = TraversalCapture(URL)
        self.assertEqual(self.audit([cap]).to_json(), self.audit([cap]).to_json())
    def test_config_invalid(self):
        with self.assertRaises(ValueError): TraversalConfig(max_findings=0)
    def test_unverified_suppressed(self):
        report = self.audit([TraversalCapture(URL)], config=TraversalConfig(include_unverified_indicators=False))
        self.assertFalse(report.findings)

if __name__ == '__main__': unittest.main()

