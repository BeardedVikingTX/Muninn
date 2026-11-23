import json
import unittest
from dataclasses import replace
from audit.ssti import SSTIAuditor, SSTIObservation, SSTIPolicy, SSTIInputError, safe_probes

URL = 'https://example.test/render?secret=hidden'

def obs(variant, text, **kw):
    return SSTIObservation(URL, 'template', 'case1', variant, text, probe_id='jinja-arithmetic', **kw)

def run(items, **kw):
    return SSTIAuditor(**kw).analyze(items, scope_check=lambda u: u.startswith('https://example.test/'))

class TestSSTI(unittest.TestCase):
    def test_no_observations(self): self.assertEqual(run([]).analyzed, 0)
    def test_safe_probe_count(self): self.assertEqual(len(safe_probes()), 4)
    def test_safe_probe_limit(self): self.assertEqual(len(safe_probes(SSTIPolicy(max_probes=2))), 2)
    def test_no_scope_callback(self):
        with self.assertRaises(SSTIInputError): SSTIAuditor().analyze([], scope_check=None)
    def test_invalid_policy(self):
        with self.assertRaises(SSTIInputError): SSTIPolicy(max_findings=0)
    def test_scope_excluded(self): self.assertEqual(run([replace(obs('expression','323'), url='https://other.test/')]).skipped_out_of_scope, 1)
    def test_bad_url(self): self.assertEqual(run([replace(obs('expression','323'), url='file:///etc/passwd')]).skipped_invalid, 1)
    def test_bad_status(self): self.assertEqual(run([replace(obs('expression','323'), status=999)]).skipped_invalid, 1)
    def test_bad_variant(self): self.assertEqual(run([replace(obs('expression','323'), variant='oops')]).skipped_invalid, 1)
    def test_bad_parameter(self): self.assertEqual(run([replace(obs('expression','323'), parameter='')]).skipped_invalid, 1)
    def test_limit(self):
        with self.assertRaises(SSTIInputError): run([obs('baseline','ok')]*3, policy=SSTIPolicy(max_observations=2))
    def test_response_size(self): self.assertEqual(run([obs('expression','abc')], policy=SSTIPolicy(max_response_chars=2)).skipped_invalid, 1)
    def test_error_only(self):
        r=run([obs('baseline','ok'),obs('expression','jinja2.exceptions.TemplateSyntaxError')]); self.assertEqual(r.findings[0].code,'template_engine_error')
    def test_error_baseline_suppression(self):
        r=run([obs('baseline','jinja2.exceptions.TemplateSyntaxError'),obs('expression','jinja2.exceptions.TemplateSyntaxError')]); self.assertFalse(r.findings)
    def test_no_controls_no_confirmation(self): self.assertFalse(run([obs('expression','323')]).findings)
    def test_medium_expression(self):
        r=run([obs('baseline','hello'),obs('literal_control','hello'),obs('expression','323')]); self.assertEqual(r.findings[0].confidence,'medium')
    def test_high_repeated(self):
        r=run([obs('baseline','hello'),obs('literal_control','hello'),obs('expression','323'),obs('repeat_expression','323')]); self.assertEqual(r.findings[0].confidence,'high')
    def test_reflection_suppressed(self):
        self.assertFalse(run([obs('baseline','hello'),obs('literal_control','hello'),obs('expression','{{ 17 * 19 }} => 323')]).findings)
    def test_answer_in_baseline_suppressed(self):
        self.assertFalse(run([obs('baseline','323'),obs('literal_control','hello'),obs('expression','323')]).findings)
    def test_answer_in_control_suppressed(self):
        self.assertFalse(run([obs('baseline','hello'),obs('literal_control','323'),obs('expression','323')]).findings)
    def test_no_partial_numeric_match(self):
        self.assertFalse(run([obs('baseline','hello'),obs('literal_control','hello'),obs('expression','13230')]).findings)
    def test_external_verified(self):
        r=run([obs('baseline','hello'),obs('literal_control','hello'),obs('expression','323', verified_evaluation=True,verification_trusted=True,verification_reference='local-lab-001')]); self.assertIn('externally_verified_template_evaluation',[f.code for f in r.findings])
    def test_external_untrusted_suppressed(self):
        r=run([obs('baseline','hello'),obs('literal_control','hello'),obs('expression','323', verified_evaluation=True,verification_reference='ref')]); self.assertNotIn('externally_verified_template_evaluation',[f.code for f in r.findings])
    def test_external_missing_reference_suppressed(self):
        r=run([obs('baseline','hello'),obs('literal_control','hello'),obs('expression','323', verified_evaluation=True,verification_trusted=True)]); self.assertNotIn('externally_verified_template_evaluation',[f.code for f in r.findings])
    def test_json_sanitizes_url_query(self):
        r=run([obs('baseline','hello'),obs('literal_control','hello'),obs('expression','323')]); self.assertNotIn('hidden',r.to_json())
    def test_json_sanitizes_parameter(self):
        r=run([replace(obs('baseline','hello'),parameter='password'),replace(obs('literal_control','hello'),parameter='password'),replace(obs('expression','323'),parameter='password')]); self.assertNotIn('password',r.to_json())
    def test_determinism(self):
        x=[obs('baseline','hello'),obs('literal_control','hello'),obs('expression','323')]; self.assertEqual(run(x).to_json(),run(list(reversed(x))).to_json())
    def test_no_unexpected_code_execution(self): self.assertTrue(all('import' not in p.expression for p in safe_probes()))
    def test_https_policy(self):
        x=replace(obs('expression','323'),url='http://example.test/'); r=SSTIAuditor(SSTIPolicy(require_https=True)).analyze([x],scope_check=lambda u:True); self.assertEqual(r.skipped_invalid,1)
    def test_invalid_input_type(self): self.assertEqual(run([None]).skipped_invalid,1)
    def test_finding_limit(self):
        x=[obs('baseline','ok'),obs('literal_control','ok'),obs('expression','323', verification_trusted=True,verified_evaluation=True,verification_reference='r')]; self.assertEqual(len(run(x,policy=SSTIPolicy(max_findings=1)).findings),1)

if __name__ == '__main__': unittest.main()

