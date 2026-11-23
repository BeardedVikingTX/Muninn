import json
import unittest
from audit.file_upload import FileUploadAuditor, UploadObservation

URL = 'https://example.test/upload'

def item(**kw):
    defaults = dict(endpoint=URL, filename='photo.png', declared_type='image/png',
                    content_prefix=b'\x89PNG\r\n\x1a\n123', status=201, accepted=True)
    defaults.update(kw)
    return UploadObservation(**defaults)

class FileUploadTests(unittest.TestCase):
    def setUp(self):
        self.auditor = FileUploadAuditor()
        self.scope = lambda url: url.startswith('https://example.test/')

    def run_audit(self, *observations):
        return self.auditor.analyze(observations, scope_check=self.scope)

    def codes(self, *observations):
        return {f.code for f in self.run_audit(*observations).findings}

    def test_valid_image_clean(self):
        self.assertEqual(self.codes(item()), set())

    def test_executable_suffix(self):
        self.assertIn('EXECUTABLE_EXTENSION_ACCEPTED', self.codes(item(filename='photo.png.php')))

    def test_nonimage_when_image_only(self):
        self.assertIn('NON_IMAGE_ACCEPTED', self.codes(item(filename='notes.txt', expected_image_only=True)))

    def test_signature_mismatch(self):
        self.assertIn('IMAGE_SIGNATURE_MISMATCH', self.codes(item(content_prefix=b'not a png')))

    def test_mime_mismatch(self):
        self.assertIn('IMAGE_MIME_MISMATCH', self.codes(item(declared_type='text/plain')))

    def test_inline_html(self):
        self.assertIn('ACTIVE_CONTENT_SERVED_INLINE', self.codes(item(retrieval_url='https://example.test/files/a', retrieval_status=200, retrieval_headers={'Content-Type': 'text/html'})))

    def test_attachment_reduces_inline_risk(self):
        self.assertNotIn('ACTIVE_CONTENT_SERVED_INLINE', self.codes(item(retrieval_url='https://example.test/files/a', retrieval_status=200, retrieval_headers={'Content-Type': 'text/html', 'Content-Disposition': 'attachment'})))

    def test_nosniff(self):
        self.assertNotIn('MISSING_NOSNIFF_ON_RETRIEVAL', self.codes(item(retrieval_url='https://example.test/files/a', retrieval_status=200, retrieval_headers={'X-Content-Type-Options': 'nosniff'})))

    def test_marker(self):
        self.assertIn('RETRIEVABLE_UPLOAD_MARKER', self.codes(item(retrieval_url='https://example.test/files/a', retrieval_status=200, marker_present_on_retrieval=True)))

    def test_rejected_upload(self):
        self.assertFalse(self.codes(item(filename='x.php', accepted=False)))

    def test_scope_fail_closed(self):
        report = self.auditor.analyze([item()], scope_check=lambda _: (_ for _ in ()).throw(RuntimeError()))
        self.assertEqual((report.analyzed, report.skipped), (0, 1))

    def test_retrieval_scope(self):
        report = self.run_audit(item(retrieval_url='https://other.test/file', retrieval_status=200))
        self.assertEqual(report.skipped, 1)

    def test_cross_origin_redirect(self):
        self.assertIn('CROSS_ORIGIN_UPLOAD_REDIRECT', self.codes(item(response_headers={'Location': 'https://other.test/file'})))

    def test_no_raw_secret_in_json(self):
        report = self.run_audit(item(filename='secret-password.php', endpoint=URL + '?token=SECRET123'))
        raw = report.to_json()
        self.assertNotIn('SECRET123', raw)
        self.assertNotIn('secret-password', raw)
        json.loads(raw)

    def test_bounded(self):
        auditor = FileUploadAuditor(max_observations=1)
        report = auditor.analyze([item(), item(filename='other.php')], scope_check=self.scope)
        self.assertEqual(report.analyzed, 1)

    def test_invalid_limit(self):
        with self.assertRaises(ValueError):
            FileUploadAuditor(max_findings=0)

if __name__ == '__main__':
    unittest.main()

