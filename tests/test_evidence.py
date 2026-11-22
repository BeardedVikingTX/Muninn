import json
import os
import tempfile
import unittest
from pathlib import Path
from core.evidence import ArtifactKind, EvidenceError, EvidenceStore, confidence_evidence, redact_text

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = EvidenceStore(Path(self.tmp.name) / 'evidence')

    def capture(self, content, **kwargs):
        return self.store.capture(finding_id='F-1', source_id='burp-12', kind=ArtifactKind.REQUEST, content=content, **kwargs)

    def test_redact_headers_and_url(self):
        record = self.capture('GET /?access_token=abc&x=1 HTTP/1.1\nAuthorization: Bearer abc123\nCookie: sid=secret\nX-Test: fine\n')
        body = (self.store.root / record.excerpt_path).read_text()
        self.assertNotIn('abc123', body)
        self.assertNotIn('sid=secret', body)
        self.assertNotIn('access_token=abc', body)
        self.assertIn('X-Test: fine', body)
        self.assertTrue(self.store.verify(record))

    def test_json_redaction(self):
        r = self.capture('{"user":"alice","nested":{"password":"secret123","access_token":"tok"}}')
        body = (self.store.root / r.excerpt_path).read_text()
        self.assertNotIn('secret123', body)
        self.assertNotIn('"tok"', body)
        self.assertIn('alice', body)

    def test_binary_not_persisted(self):
        r = self.capture(b'private\x00stuff')
        self.assertTrue(r.truncated)
        self.assertEqual((self.store.root / r.excerpt_path).read_text(), '[BINARY CONTENT OMITTED]')

    def test_reject_path_traversal(self):
        with self.assertRaises(ValueError):
            self.store.capture(finding_id='../escape', source_id='x', kind=ArtifactKind.OTHER, content='hi')

    def test_duplicate_id(self):
        self.capture('one', evidence_id='same')
        with self.assertRaises(EvidenceError):
            self.capture('two', evidence_id='same')

    def test_size_limit(self):
        with self.assertRaises(EvidenceError):
            self.capture('x' * (2 * 1024 * 1024 + 1))

    def test_manifest_and_integrity(self):
        r = self.capture('hello', metadata={'note':'ok'})
        manifest = json.loads((self.store.root / f'{r.evidence_id}.json').read_text())
        self.assertEqual(manifest['original_size'], 5)
        self.assertTrue(self.store.verify(r))
        (self.store.root / r.excerpt_path).write_text('tampered')
        self.assertFalse(self.store.verify(r))

    def test_permissions(self):
        r = self.capture('hi')
        self.assertEqual(self.store.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.store.root / r.excerpt_path).stat().st_mode & 0o777, 0o600)

    def test_confidence_adapter_not_validated(self):
        r = self.capture('test')
        ev = confidence_evidence(r)
        self.assertFalse(ev.controlled)
        self.assertFalse(ev.reproducible)

    def test_metadata_redaction(self):
        r = self.capture('x', metadata={'authorization':'Bearer abcdef'})
        self.assertNotIn('abcdef', r.to_json())

if __name__ == '__main__':
    unittest.main()

