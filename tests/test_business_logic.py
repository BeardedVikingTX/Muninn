import unittest
import json
from dataclasses import replace
from audit.business_logic import BusinessLogicAuditor, Event, Rule, ValidationError

URL = 'https://example.test/api/checkout'
def event(step='pay', sequence=1, **kw):
    return Event('checkout', step, sequence, 'POST', URL, 200, actor='tester', resource='order1', **kw)
def rule(kind, **config):
    return Rule('test', kind, 'checkout', config=config)
def run(events, r, **kw):
    return BusinessLogicAuditor(**kw).analyze(events, [r], scope_check=lambda u: u == URL)

class Tests(unittest.TestCase):
    def test_required_predecessor_detects(self):
        self.assertEqual(len(run([event()], rule('required_predecessor', step='pay', prior_step='cart')).findings), 1)
    def test_required_predecessor_ok(self):
        self.assertFalse(run([event('cart', 0), event()], rule('required_predecessor', step='pay', prior_step='cart')).findings)
    def test_predecessor_later_not_valid(self):
        self.assertEqual(len(run([event(), event('cart', 2)], rule('required_predecessor', step='pay', prior_step='cart')).findings), 1)
    def test_predecessor_failed_not_valid(self):
        self.assertEqual(len(run([replace(event('cart', 0), status=403), event()], rule('required_predecessor', step='pay', prior_step='cart')).findings), 1)
    def test_unique_success(self):
        self.assertEqual(len(run([event(), event(sequence=2)], rule('unique_success', step='pay')).findings), 1)
    def test_unique_success_distinct_resources(self):
        self.assertFalse(run([event(), replace(event(sequence=2), resource='order2')], rule('unique_success', step='pay')).findings)
    def test_maximum_successes(self):
        self.assertEqual(len(run([event(), event(sequence=2), event(sequence=3)], rule('maximum_successes', step='pay', limit=2)).findings), 1)
    def test_maximum_successes_rejects_negative(self):
        with self.assertRaises(ValidationError): run([event()], rule('maximum_successes', step='pay', limit=-1))
    def test_fact_equals(self):
        self.assertEqual(len(run([event(facts={'quantity': 2})], rule('fact_equals', step='pay', fact='quantity', expected=1)).findings), 1)
    def test_fact_equals_missing_is_not_failure(self):
        self.assertFalse(run([event()], rule('fact_equals', step='pay', fact='quantity', expected=1)).findings)
    def test_decimal_balance(self):
        self.assertEqual(len(run([event(facts={'before':'10.00','delta':'-2.00','after':'9.00'})], rule('decimal_balance', step='pay', before='before', delta='delta', after='after')).findings), 1)
    def test_decimal_balance_exact(self):
        self.assertFalse(run([event(facts={'before':'10.00','delta':'-2.00','after':'8.00'})], rule('decimal_balance', step='pay', before='before', delta='delta', after='after')).findings)
    def test_float_rejected_for_money(self):
        with self.assertRaises(ValidationError): run([event(facts={'before':10.1,'delta':'-2','after':'8'})], rule('decimal_balance', step='pay', before='before', delta='delta', after='after'))
    def test_role_gate(self):
        self.assertEqual(len(run([event(role='viewer')], rule('role_gate', step='pay', allowed_roles=['admin'])).findings), 1)
    def test_role_gate_ok(self):
        self.assertFalse(run([event(role='admin')], rule('role_gate', step='pay', allowed_roles=['admin'])).findings)
    def test_idempotency(self):
        events=[event(facts={'key':'k','result':'a'}),event(sequence=2,facts={'key':'k','result':'b'})]
        self.assertEqual(len(run(events, rule('idempotency', step='pay', key_fact='key', result_fact='result')).findings), 1)
    def test_idempotency_same_result(self):
        events=[event(facts={'key':'k','result':'a'}),event(sequence=2,facts={'key':'k','result':'a'})]
        self.assertFalse(run(events, rule('idempotency', step='pay', key_fact='key', result_fact='result')).findings)
    def test_monotonic(self):
        events=[event(facts={'count':'4'}),event(sequence=2,facts={'count':'3'})]
        self.assertEqual(len(run(events, rule('monotonic_fact', step='pay', fact='count', direction='nondecreasing')).findings), 1)
    def test_monotonic_ok(self):
        events=[event(facts={'count':'3'}),event(sequence=2,facts={'count':'4'})]
        self.assertFalse(run(events, rule('monotonic_fact', step='pay', fact='count', direction='nondecreasing')).findings)
    def test_cross_actor(self):
        events=[event(),replace(event(sequence=2), actor='peer')]
        self.assertEqual(len(run(events, rule('cross_actor_success', step='pay')).findings), 1)
    def test_cross_actor_single(self):
        self.assertFalse(run([event()], rule('cross_actor_success', step='pay')).findings)
    def test_transition(self):
        self.assertEqual(len(run([event('start', 1), event('finish', 2)], rule('allowed_transition', from_step='start', to_step='finish')).findings), 1)
    def test_scope_excludes(self):
        report=BusinessLogicAuditor().analyze([event()], [rule('unique_success', step='pay')], scope_check=lambda _: False)
        self.assertEqual((report.scoped, report.skipped), (0,1))
    def test_scope_exception_fails_closed(self):
        def bad(_): raise RuntimeError('no')
        report=BusinessLogicAuditor().analyze([event()], [rule('unique_success', step='pay')], scope_check=bad)
        self.assertEqual(report.scoped, 0)
    def test_scope_required(self):
        with self.assertRaises(ValidationError): BusinessLogicAuditor().analyze([], [], scope_check=None)
    def test_invalid_url(self):
        with self.assertRaises(ValidationError): run([replace(event(), url='file:///etc/passwd')], rule('unique_success', step='pay'))
    def test_credentials_in_url_rejected(self):
        with self.assertRaises(ValidationError): run([replace(event(), url='https://u:p@example.test/')], rule('unique_success', step='pay'))
    def test_event_limit(self):
        with self.assertRaises(ValidationError): run([event(), event(sequence=2)], rule('unique_success', step='pay'), max_events=1)
    def test_rule_limit(self):
        with self.assertRaises(ValidationError): BusinessLogicAuditor(max_rules=1).analyze([], [rule('unique_success', step='pay'), Rule('second','unique_success','checkout',config={'step':'pay'})],scope_check=lambda _: True)
    def test_duplicate_rule_ids(self):
        with self.assertRaises(ValidationError): BusinessLogicAuditor().analyze([], [rule('unique_success', step='pay')]*2, scope_check=lambda _: True)
    def test_finding_limit(self):
        r=run([event(),event(sequence=2),event(sequence=3)], rule('required_predecessor',step='pay',prior_step='cart'),max_findings=1)
        self.assertEqual(len(r.findings),1)
        self.assertTrue(r.diagnostics)
    def test_json_does_not_include_url_or_actor(self):
        r=run([replace(event(), actor='secret-principal')],rule('required_predecessor',step='pay',prior_step='cart'))
        data=r.to_json()
        self.assertNotIn('secret-principal',data)
        self.assertNotIn('example.test',data)
        json.loads(data)
    def test_determinism(self):
        events=[event(sequence=2),event(sequence=1)]
        r=rule('required_predecessor',step='pay',prior_step='cart')
        self.assertEqual(run(events,r).to_json(),run(list(reversed(events)),r).to_json())
    def test_bad_fact_name(self):
        with self.assertRaises(ValidationError): run([event(facts={'Authorization: Bearer secret': 'x'})],rule('unique_success',step='pay'))
    def test_missing_evidence_diagnostic(self):
        r=BusinessLogicAuditor().analyze([], [rule('unique_success',step='pay')],scope_check=lambda _:True)
        self.assertEqual(len(r.diagnostics),1)

if __name__=='__main__': unittest.main()

