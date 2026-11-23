import json
import unittest
from dataclasses import replace
from audit.broken_access_control import (
    AccessObservation, BrokenAccessControlAuditor, FindingKind,
)

URL = 'https://example.test/api/documents/42?token=DO_NOT_LOG'
FP = 'a' * 64

def capture(role='owner', expected=True, status=200, **kw):
    return AccessObservation(method='GET', url=URL, resource_key='secret-document-42',
                             principal_key=role, role=role, expected_access=expected,
                             status=status, **kw)

class BrokenAccessControlTests(unittest.TestCase):
    def setUp(self):
        self.a = BrokenAccessControlAuditor()
        self.scope = lambda url: url.startswith('https://example.test/')

    def analyze(self, items, **kwargs):
        return self.a.analyze(items, scope_check=self.scope, **kwargs)

    def test_peer_success(self):
        r = self.analyze([capture(), capture('peer', False)])
        self.assertEqual(r.findings[0].kind, FindingKind.CROSS_PRINCIPAL_ACCESS)

    def test_anonymous_success(self):
        r = self.analyze([capture(), capture('anonymous', False)])
        self.assertEqual(r.findings[0].kind, FindingKind.ANONYMOUS_ACCESS)

    def test_invalid_success(self):
        r = self.analyze([capture(), capture('invalid', False)])
        self.assertEqual(r.findings[0].kind, FindingKind.ANONYMOUS_ACCESS)

    def test_expired_success(self):
        r = self.analyze([capture(), capture('expired', False)])
        self.assertEqual(r.findings[0].kind, FindingKind.ANONYMOUS_ACCESS)

    def test_admin_denied_but_success(self):
        r = self.analyze([capture(), capture('admin', False)])
        self.assertEqual(r.findings[0].kind, FindingKind.PRIVILEGE_BOUNDARY)

    def test_expected_denial(self):
        self.assertFalse(self.analyze([capture(), capture('peer', False, 403)]).findings)

    def test_no_baseline(self):
        self.assertFalse(self.analyze([capture('peer', False)]).findings)

    def test_unknown_access(self):
        self.assertFalse(self.analyze([capture(), capture('peer', None)]).findings)

    def test_owner_failure(self):
        self.assertFalse(self.analyze([capture(status=401), capture('peer', False)]).findings)

    def test_different_resources(self):
        peer = replace(capture('peer', False), resource_key='another')
        self.assertFalse(self.analyze([capture(), peer]).findings)

    def test_different_methods(self):
        peer = replace(capture('peer', False), method='POST')
        self.assertFalse(self.analyze([capture(), peer]).findings)

    def test_different_scenarios(self):
        peer = replace(capture('peer', False), scenario_key='other')
        self.assertFalse(self.analyze([capture(), peer]).findings)

    def test_different_paths(self):
        peer = replace(capture('peer', False), url='https://example.test/api/other/42')
        self.assertFalse(self.analyze([capture(), peer]).findings)

    def test_different_hosts(self):
        peer = replace(capture('peer', False), url='https://other.test/api/documents/42')
        r = self.a.analyze([capture(), peer], scope_check=lambda _: True)
        self.assertFalse(r.findings)

    def test_out_of_scope(self):
        r = self.a.analyze([capture(), capture('peer', False)], scope_check=lambda _: False)
        self.assertEqual(r.skipped_out_of_scope, 2)

    def test_scope_exception_fail_closed(self):
        def fail(_): raise RuntimeError('oops')
        r = self.a.analyze([capture()], scope_check=fail)
        self.assertEqual(r.skipped_out_of_scope, 1)

    def test_scope_required(self):
        with self.assertRaises(TypeError): self.a.analyze([capture()], scope_check=None)

    def test_bad_url(self):
        r = self.analyze([replace(capture(), url='file:///etc/passwd')])
        self.assertEqual(r.skipped_invalid, 1)

    def test_bad_role(self):
        r = self.analyze([replace(capture(), role='superuser')])
        self.assertEqual(r.skipped_invalid, 1)

