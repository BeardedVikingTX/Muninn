import unittest
from audit.mass_assignment import (
    AssignmentCapture, AssignmentPolicy, MassAssignmentAuditor, flatten_fields,
)

URL = 'https://example.test/api/profile?token=secret'
POLICY = AssignmentPolicy('profile_update', frozenset({'display_name'}), frozenset({'is_admin'}))

def capture(**kwargs):
    data = dict(operation='profile_update', method='PATCH', url=URL,
                principal_id='tester', object_id='test-user',
                request_json={'is_admin': True}, status=200)
    data.update(kwargs)
    return AssignmentCapture(**data)

class MassAssignmentTests(unittest.TestCase):
    def setUp(self):
        self.auditor = MassAssignmentAuditor()
        self.scope = lambda url: url.startswith('https://example.test/')

    def test_flatten_nested(self):
        self.assertEqual(flatten_fields({'user': {'role': 'admin'}}), {'user.role': 'admin'})

    def test_flatten_list(self):
        self.assertEqual(flatten_fields({'a': [1, 2]}), {'a[0]': 1, 'a[1]': 2})

    def test_allowed_field_ignored(self):
        result = self.auditor.analyze([capture(request_json={'display_name': 'A'})], [POLICY], scope_check=self.scope)
        self.assertEqual(len(result.findings), 0)

    def test_suspicious_submission_low(self):
        result = self.auditor.analyze([capture()], [POLICY], scope_check=self.scope)
        self.assertEqual(result.findings[0].confidence, 'low')

    def test_trusted_change_high(self):
        result = self.auditor.analyze([capture(before_json={'is_admin': False}, after_json={'is_admin': True}, snapshots_trusted=True)], [POLICY], scope_check=self.scope)
        self.assertEqual(result.findings[0].code, 'PROTECTED_FIELD_CHANGED')
        self.assertEqual(result.findings[0].confidence, 'high')

    def test_untrusted_snapshots_not_high(self):
        result = self.auditor.analyze([capture(before_json={'is_admin': False}, after_json={'is_admin': True})], [POLICY], scope_check=self.scope)
        self.assertEqual(result.findings[0].confidence, 'low')

    def test_unchanged_not_high(self):
        result = self.auditor.analyze([capture(before_json={'is_admin': True}, after_json={'is_admin': True}, snapshots_trusted=True)], [POLICY], scope_check=self.scope)
        self.assertEqual(result.findings[0].confidence, 'low')

    def test_denied_not_finding(self):
        result = self.auditor.analyze([capture(status=403)], [POLICY], scope_check=self.scope)
        self.assertFalse(result.findings)

    def test_out_of_scope(self):
        result = self.auditor.analyze([capture(url='https://other.test/profile')], [POLICY], scope_check=self.scope)
        self.assertEqual(result.captures_skipped, 1)

    def test_scope_failure_closed(self):
        def broken(url): raise RuntimeError('failure')
        result = self.auditor.analyze([capture()], [POLICY], scope_check=broken)
        self.assertFalse(result.findings)

    def test_missing_policy(self):
        result = self.auditor.analyze([capture()], [], scope_check=self.scope)
        self.assertEqual(result.captures_skipped, 1)

    def test_deduplication(self):
        result = self.auditor.analyze([capture(), capture()], [POLICY], scope_check=self.scope)
        self.assertEqual(len(result.findings), 1)

    def test_no_secret_in_report(self):
        result = self.auditor.analyze([capture()], [POLICY], scope_check=self.scope)
        self.assertNotIn('token=secret', result.to_json())
        self.assertNotIn('test-user', result.to_json())

    def test_max_findings(self):
        auditor = MassAssignmentAuditor(max_findings=1)
        result = auditor.analyze([capture(request_json={'is_admin': True, 'role': 'admin'})], [POLICY], scope_check=self.scope)
        self.assertEqual(len(result.findings), 1)

    def test_invalid_limits(self):
        with self.assertRaises(ValueError): MassAssignmentAuditor(max_captures=0)

    def test_policy_overlap(self):
        with self.assertRaises(ValueError): AssignmentPolicy('test', frozenset({'role'}), frozenset({'role'}))

    def test_unknown_field(self):
        result = self.auditor.analyze([capture(request_json={'custom_field': 1})], [POLICY], scope_check=self.scope)
        self.assertEqual(result.findings[0].code, 'UNAUTHORIZED_FIELD_SUBMITTED')

    def test_unknown_allowed(self):
        policy = AssignmentPolicy('profile_update', frozenset({'display_name'}), allow_unknown_fields=True)
        result = self.auditor.analyze([capture(request_json={'custom_field': 1})], [policy], scope_check=self.scope)
        self.assertFalse(result.findings)

if __name__ == '__main__': unittest.main()

