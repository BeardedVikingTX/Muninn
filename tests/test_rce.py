import json
import unittest
from audit.rce import RCEAuditor, RCEObservation, _origin

URL = 'https://test.example/api/execute?token=SECRET'
SCOPE = lambda url: url.startswith('https://test.example/')

class RCETests(unittest.TestCase):
    def run_one(self, **kw):
        return RCEAuditor().analyze([RCEObservation(url=URL, **kw)], scope_check=SCOPE)

    def cats(self, **kw):
        return {f.category for f in self.run_one(**kw).findings}

    def test_empty(self): self.assertEqual(self.cats(), set())
    def test_scope_required(self):
        with self.assertRaises(TypeError): RCEAuditor().analyze([], scope_check=None)
    def test_scope_skip(self):
        r = RCEAuditor().analyze([RCEObservation(url=URL)], scope_check=lambda _: False)
        self.assertEqual((r.analyzed, r.skipped_out_of_scope), (0, 1))
    def test_invalid_url(self):
        with self.assertRaises(ValueError): self.run_one_dummy('file:///etc/passwd')
    def run_one_dummy(self, url): return RCEAuditor().analyze([RCEObservation(url=url)], scope_check=lambda _: True)
    def test_userinfo_url(self):
        with self.assertRaises(ValueError): _origin('https://u:p@example.test/')
    def test_command_sink(self): self.assertIn('potential_command_sink', self.cats(source_code='subprocess.run(args)'))
    def test_eval_sink(self): self.assertIn('potential_evaluation_sink', self.cats(source_code='eval(input)'))
    def test_template_sink(self): self.assertIn('potential_template_sink', self.cats(source_code='render_template_string(x)'))
    def test_deserialization_sink(self): self.assertIn('potential_deserialization_sink', self.cats(source_code='pickle.loads(blob)'))
    def test_shell_error(self): self.assertIn('shell_error', self.cats(response_text='/bin/sh: command not found'))
    def test_error_in_baseline(self): self.assertNotIn('shell_error', self.cats(response_text='/bin/sh: command not found', baseline_response_text='/bin/sh: command not found'))
    def test_trace(self): self.assertIn('runtime_trace', self.cats(response_text='Traceback (most recent call last)'))
    def test_template_error(self): self.assertIn('template_error', self.cats(response_text='TemplateSyntaxError'))
    def test_status_anomaly(self): self.assertIn('status_anomaly', self.cats(status=500, baseline_status=200))
    def test_status_same(self): self.assertNotIn('status_anomaly', self.cats(status=200, baseline_status=200))
    def test_timing_insufficient_samples(self): self.assertNotIn('timing_anomaly', self.cats(timing_ms=5000, baseline_timing_ms=100, timing_samples=2, baseline_timing_samples=2))
    def test_timing_anomaly(self): self.assertIn('timing_anomaly', self.cats(timing_ms=5000, baseline_timing_ms=100, timing_samples=6, baseline_timing_samples=6))
    def test_timing_nonfinite(self): self.assertNotIn('timing_anomaly', self.cats(timing_ms=float('nan'), baseline_timing_ms=100, timing_samples=6, baseline_timing_samples=6))
    def test_headers(self): self.assertIn('runtime_header', self.cats(response_headers={'X-Powered-By':'Express'}))
    def test_marker_unverified(self): self.assertNotIn('verified_execution_marker', self.cats(marker_expected='abc', marker_observed='abc'))
    def test_marker_missing_provenance(self): self.assertIn('marker_claim_incomplete', self.cats(marker_verified=True, marker_expected='abc', marker_observed='abc'))
    def test_marker_verified(self): self.assertIn('verified_execution_marker', self.cats(marker_verified=True, marker_expected='abc', marker_observed='abc', test_fixture_id='fixture1', verification_method='trusted-control'))
    def test_marker_mismatch(self): self.assertNotIn('verified_execution_marker', self.cats(marker_verified=True, marker_expected='abc', marker_observed='xyz', test_fixture_id='fixture1', verification_method='trusted-control'))
    def test_execution_verified(self): self.assertIn('verified_execution', self.cats(execution_verified=True, test_fixture_id='fixture1', verification_method='trusted-control'))
    def test_execution_unproven(self): self.assertIn('execution_claim_incomplete', self.cats(execution_verified=True))
    def test_redaction(self):
        report = self.run_one(response_text='Traceback (most recent call last) SECRET', source_code='eval("PASSWORD")')
        self.assertNotIn('SECRET', report.to_json()); self.assertNotIn('PASSWORD', report.to_json())
    def test_determinism(self): self.assertEqual(self.run_one(source_code='eval(x)').to_json(), self.run_one(source_code='eval(x)').to_json())
    def test_dedup(self):
        r = RCEAuditor().analyze([RCEObservation(url=URL, source_code='eval(x)')]*2, scope_check=SCOPE)
        self.assertEqual(len(r.findings), 1)
    def test_max_observations(self):
        r = RCEAuditor(max_observations=1).analyze([RCEObservation(url=URL)]*2, scope_check=SCOPE)
        self.assertTrue(r.truncated); self.assertEqual(r.analyzed, 1)
    def test_max_findings(self):
        r = RCEAuditor(max_findings=1).analyze([RCEObservation(url=URL, source_code='eval(x);pickle.loads(x)')], scope_check=SCOPE)
        self.assertTrue(r.truncated); self.assertEqual(len(r.findings), 1)
    def test_invalid_limits(self):
        with self.assertRaises(ValueError): RCEAuditor(max_observations=0)
    def test_json_schema(self):
        data = json.loads(self.run_one(source_code='eval(x)').to_json())
        self.assertEqual(data['analyzed'], 1); self.assertEqual(data['findings'][0]['confidence'], 'low')
    def test_no_200_proof(self): self.assertNotIn('verified_execution', self.cats(status=200))
    def test_scope_callback_called(self):
        seen = []
        RCEAuditor().analyze([RCEObservation(url=URL)], scope_check=lambda url: seen.append(url) or True)
        self.assertEqual(seen, [URL])

if __name__ == '__main__': unittest.main()


