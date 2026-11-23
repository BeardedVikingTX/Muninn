import unittest
import json
from dataclasses import replace
from audit.race_conditions import RaceConditionsAuditor, RaceObservation, RacePolicy, _overlap_count

URL = 'https://example.test/api/redeem'
P = RacePolicy('coupon')
def obs(n, *, committed=None, verified=False, start=0, end=100, status=200, **kwargs):
    return RaceObservation(URL, 'coupon', 'run-1', str(n), 'coupon-1', 'tester',
                           start, end, status, committed, verified, **kwargs)

def scan(items, policies=(P,), **kwargs):
    return RaceConditionsAuditor(**kwargs).analyze(items, policies, scope_check=lambda url: url == URL)

class RaceTests(unittest.TestCase):
    def test_verified_double_commit(self):
        f = scan([obs(1, committed=True, verified=True), obs(2, committed=True, verified=True)]).findings[0]
        self.assertEqual((f.rule, f.confidence), ('verified_commit_limit_exceeded', 'high'))
    def test_two_200_only_low(self):
        self.assertEqual(scan([obs(1), obs(2)]).findings[0].confidence, 'low')
    def test_no_overlap(self):
        self.assertFalse(scan([obs(1, end=10), obs(2, start=10, end=20)]).findings)
    def test_overlap_disabled(self):
        self.assertEqual(len(scan([obs(1, end=10), obs(2, start=10, end=20)],
                                  policies=(RacePolicy('coupon', require_overlap=False),)).findings), 1)
    def test_only_one_committed_but_two_200(self):
        self.assertEqual(scan([obs(1, committed=True, verified=True),
                               obs(2, committed=False, verified=True)]).findings[0].confidence, 'low')
    def test_both_rejected(self):
        self.assertFalse(scan([obs(1, status=409), obs(2, status=409)]).findings)
    def test_policy_allows_two(self):
        self.assertFalse(scan([obs(1), obs(2)], policies=(RacePolicy('coupon', max_committed=2),)).findings)
    def test_three_commits_allowed_two(self):
        self.assertEqual(scan([obs(i, committed=True, verified=True) for i in range(3)],
                              policies=(RacePolicy('coupon', max_committed=2),)).findings[0].confidence, 'high')
    def test_dedupe(self):
        r = scan([obs(1), obs(1), obs(2)])
        self.assertEqual((r.analyzed, r.skipped), (2, 1))
    def test_out_of_scope(self):
        r = scan([replace(obs(1), url='https://other.test/'), obs(2)])
        self.assertEqual((r.analyzed, r.skipped), (1, 1))
    def test_invalid_url(self):
        self.assertEqual(scan([replace(obs(1), url='file:///etc/passwd')]).skipped, 1)
    def test_userinfo_url(self):
        self.assertEqual(scan([replace(obs(1), url='https://x@y.test/')]).skipped, 1)
    def test_invalid_interval(self):
        self.assertEqual(scan([obs(1, start=20, end=10)]).skipped, 1)
    def test_nan(self):
        self.assertEqual(scan([obs(1, start=float('nan'))]).skipped, 1)
    def test_unverified_flag_without_value(self):
        self.assertEqual(scan([obs(1, verified=True)]).skipped, 1)
    def test_no_policy(self):
        self.assertEqual(scan([obs(1)], policies=()).skipped, 1)
    def test_duplicate_policy(self):
        with self.assertRaises(ValueError): scan([], policies=(P, P))
    def test_scope_required(self):
        with self.assertRaises(TypeError): RaceConditionsAuditor().analyze([], [P], scope_check=None)
    def test_limits(self):
        with self.assertRaises(ValueError): scan([obs(1), obs(2), obs(3)], max_observations=2)
    def test_group_limit(self):
        with self.assertRaises(ValueError): scan([obs(1), obs(2)], max_group_size=1)
    def test_invalid_config(self):
        with self.assertRaises(ValueError): RaceConditionsAuditor(max_findings=0)
    def test_invalid_policy(self):
        with self.assertRaises(ValueError): RacePolicy('coupon', max_committed=-1)
    def test_json_redaction(self):
        result = scan([obs(1), obs(2)]).to_json()
        self.assertNotIn('coupon-1', result)
        self.assertNotIn('run-1', result)
        self.assertNotIn(URL, result)
        self.assertEqual(json.loads(result)['analyzed'], 2)
    def test_idempotency_reuse(self):
        f = scan([obs(1, idempotency_key='key1'), obs(2, idempotency_key='key1')]).findings[0]
        self.assertTrue(f.evidence['reused_idempotency_key'])
        self.assertNotIn('key1', json.dumps(f.evidence))
    def test_different_resources(self):
        r = scan([obs(1), replace(obs(2), resource_id='other')])
        self.assertFalse(r.findings)
    def test_different_runs(self):
        r = scan([obs(1), replace(obs(2), run_id='other')])
        self.assertFalse(r.findings)
    def test_end_exclusive(self):
        self.assertEqual(_overlap_count([obs(1, end=10), obs(2, start=10, end=20)]), 1)
    def test_sorted_deterministic(self):
        a = [obs(1), obs(2), replace(obs(3), run_id='z'), replace(obs(4), run_id='z')]
        self.assertEqual(scan(a).to_json(), scan(list(reversed(a))).to_json())

if __name__ == '__main__': unittest.main()

