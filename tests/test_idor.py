import unittest
from audit.idor import IDORAuditor, IDORCapture

URL = 'https://example.test/api/documents/42?token=SECRET'

def cap(principal='owner', allowed=True, status=200, **kwargs):
    return IDORCapture(method='GET', url=URL, resource_id='doc-42',
                       principal_id=principal, expected_access=allowed,
                       status=status, **kwargs)

class IDORTests(unittest.TestCase):
    def setUp(self):
        self.a = IDORAuditor()
        self.scope = lambda u: u.startswith('https://example.test/')

    def analyze(self, *captures):
        return self.a.analyze(captures, scope_check=self.scope)

    def test_empty(self):
        self.assertEqual(self.analyze().findings, ())

    def test_denied_response(self):
        self.assertFalse(self.analyze(cap(), cap('peer', False, 403)).findings)

    def test_no_baseline(self):
        self.assertFalse(self.analyze(cap('peer', False)).findings)

    def test_success_indicator(self):
        self.assertEqual(self.analyze(cap(), cap('peer', False)).findings[0].confidence, 'low')

    def test_matching_fingerprint(self):
        r = self.analyze(cap(response_fingerprint='hash'), cap('peer', False, response_fingerprint='hash'))
        self.assertEqual(r.findings[0].confidence, 'medium')

    def test_nonmatching_fingerprint(self):
        r = self.analyze(cap(response_fingerprint='one'), cap('peer', False, response_fingerprint='two'))
        self.assertEqual(r.findings[0].confidence, 'low')

    def test_confirmed_fixture(self):
        r = self.analyze(cap(), cap('peer', False, response_resource_id='doc-42', confirmed_resource_disclosure=True))
        self.assertEqual(r.findings[0].severity, 'high')

    def test_mismatched_resource_not_confirmed(self):
        r = self.analyze(cap(), cap('peer', False, response_resource_id='other', confirmed_resource_disclosure=True))
        self.assertEqual(r.findings[0].confidence, 'low')

    def test_scope_skip(self):
        r = self.a.analyze([cap()], scope_check=lambda _: False)
        self.assertEqual((r.analyzed, r.skipped), (0, 1))

    def test_scope_failure(self):
        with self.assertRaises(RuntimeError):
            self.a.analyze([cap()], scope_check=lambda _: (_ for _ in ()).throw(RuntimeError('deny')))

    def test_missing_scope(self):
        with self.assertRaises(TypeError):
            self.a.analyze([cap()], scope_check=None)

    def test_invalid_url(self):
        with self.assertRaises(ValueError):
            self.analyze(IDORCapture('GET', 'file:///etc/passwd', 'r', 'p', True, 200))

    def test_invalid_status(self):
        with self.assertRaises(ValueError):
            self.analyze(cap(status=999))

    def test_limits(self):
        with self.assertRaises(ValueError):
            IDORAuditor(max_captures=1).analyze([cap(), cap()], scope_check=self.scope)

    def test_redaction(self):
        result = self.analyze(cap(), cap('peer', False)).to_json()
        for secret in ('SECRET', 'doc-42', 'peer', '/api/documents/42'):
            self.assertNotIn(secret, result)

    def test_determinism(self):
        captures = [cap(), cap('peer', False)]
        self.assertEqual(self.analyze(*captures).to_json(), self.analyze(*captures).to_json())

    def test_duplicate(self):
        self.assertEqual(len(self.analyze(cap(), cap('peer', False), cap('peer', False)).findings), 1)

    def test_other_method_not_grouped(self):
        other = IDORCapture('POST', URL, 'doc-42', 'peer', False, 200)
        self.assertFalse(self.analyze(cap(), other).findings)

    def test_other_scenario_not_grouped(self):
        self.assertFalse(self.analyze(cap(), cap('peer', False, scenario='different')).findings)

    def test_other_resource_not_grouped(self):
        self.assertFalse(self.analyze(cap(), IDORCapture('GET', URL, 'doc-43', 'peer', False, 200)).findings)

    def test_no_network(self):
        self.assertFalse(hasattr(self.a, 'send'))

if __name__ == '__main__':
    unittest.main()

