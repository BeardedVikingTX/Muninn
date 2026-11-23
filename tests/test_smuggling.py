import unittest
from audit.smuggling import SmugglingAuditor, SmugglingCapture, SmugglingConfig

URL = 'https://example.test/api'

def request(headers=b'', body=b''):
    return b'POST /api HTTP/1.1\r\nHost: example.test\r\n' + headers + b'\r\n' + body

def codes(raw, **kwargs):
    report = SmugglingAuditor().analyze([SmugglingCapture(URL, raw, **kwargs)], scope_check=lambda u: True)
    return {f.code for f in report.findings}

class Tests(unittest.TestCase):
    def test_normal(self): self.assertEqual(codes(request(b'Content-Length: 0\r\n')), set())
    def test_cl_te(self): self.assertIn('CL_TE_AMBIGUITY', codes(request(b'Content-Length: 0\r\nTransfer-Encoding: chunked\r\n')))
    def test_duplicate_cl(self): self.assertIn('DUPLICATE_CONTENT_LENGTH', codes(request(b'Content-Length: 1\r\nContent-Length: 1\r\n')))
    def test_conflicting_cl(self): self.assertIn('CONFLICTING_CONTENT_LENGTH', codes(request(b'Content-Length: 1\r\nContent-Length: 2\r\n')))
    def test_invalid_cl(self): self.assertIn('INVALID_CONTENT_LENGTH', codes(request(b'Content-Length: -1\r\n')))
    def test_cl_comma(self): self.assertIn('INVALID_CONTENT_LENGTH', codes(request(b'Content-Length: 1, 1\r\n')))
    def test_obsolete_fold(self): self.assertIn('OBSOLETE_LINE_FOLDING', codes(request(b'X-Test: a\r\n continued\r\n')))
    def test_whitespace_colon(self): self.assertIn('WHITESPACE_BEFORE_COLON', codes(request(b'Content-Length : 0\r\n')))
    def test_invalid_name(self): self.assertIn('INVALID_HEADER_NAME', codes(request(b'Bad Name: x\r\n')))
    def test_missing_colon(self): self.assertIn('MALFORMED_HEADER', codes(request(b'broken\r\n')))
    def test_no_terminator(self): self.assertIn('INVALID_HEADER_BOUNDARY', codes(b'GET / HTTP/1.1\r\nHost: x'))
    def test_invalid_request_line(self): self.assertIn('INVALID_REQUEST_LINE', codes(b'BAD\r\nHost: x\r\n\r\n'))
    def test_multiple_te(self): self.assertIn('MULTIPLE_TRANSFER_ENCODING', codes(request(b'Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n')))
    def test_nonfinal_chunked(self): self.assertIn('NONFINAL_CHUNKED', codes(request(b'Transfer-Encoding: chunked, gzip\r\n')))
    def test_repeated_chunked(self): self.assertIn('REPEATED_CHUNKED', codes(request(b'Transfer-Encoding: chunked, chunked\r\n')))
    def test_empty_te(self): self.assertIn('INVALID_TRANSFER_ENCODING', codes(request(b'Transfer-Encoding: gzip,\r\n')))
    def test_suspicious_te(self): self.assertIn('SUSPICIOUS_TRANSFER_ENCODING', codes(request(b'Transfer-Encoding: chunked;foo=x\r\n')))
    def test_h2_label(self): self.assertIn('H2_CAPTURE_AS_HTTP1', codes(request(), protocol='h2'))
    def test_verified(self): self.assertIn('VERIFIED_PARSER_DISAGREEMENT', codes(request(), parser_outcomes_trusted=True, isolated_test=True, frontend_consumed_bytes=10, backend_consumed_bytes=20))
    def test_untrusted_not_verified(self): self.assertNotIn('VERIFIED_PARSER_DISAGREEMENT', codes(request(), parser_outcomes_trusted=False, isolated_test=True, frontend_consumed_bytes=10, backend_consumed_bytes=20))
    def test_nonisolated_not_verified(self): self.assertNotIn('VERIFIED_PARSER_DISAGREEMENT', codes(request(), parser_outcomes_trusted=True, isolated_test=False, frontend_consumed_bytes=10, backend_consumed_bytes=20))
    def test_invalid_boundaries_not_verified(self): self.assertNotIn('VERIFIED_PARSER_DISAGREEMENT', codes(request(), parser_outcomes_trusted=True, isolated_test=True, frontend_consumed_bytes=-1, backend_consumed_bytes=20))
    def test_scope(self):
        r = SmugglingAuditor().analyze([SmugglingCapture(URL, request())], scope_check=lambda u: False)
        self.assertEqual((r.inspected, r.skipped), (0, 1))
    def test_invalid_url(self):
        r = SmugglingAuditor().analyze([SmugglingCapture('file:///tmp/x', request())], scope_check=lambda u: True)
        self.assertEqual(r.skipped, 1)
    def test_bytes_limit(self):
        r = SmugglingAuditor(SmugglingConfig(max_request_bytes=10)).analyze([SmugglingCapture(URL, request())], scope_check=lambda u: True)
        self.assertEqual(r.skipped, 1)
    def test_header_limit(self):
        r = SmugglingAuditor(SmugglingConfig(max_header_bytes=5)).analyze([SmugglingCapture(URL, request())], scope_check=lambda u: True)
        self.assertEqual(r.findings[0].code, 'HEADER_LIMIT_EXCEEDED')
    def test_header_count_limit(self):
        r = SmugglingAuditor(SmugglingConfig(max_headers=1)).analyze([SmugglingCapture(URL, request(b'A: 1\r\n'))], scope_check=lambda u: True)
        self.assertIn('HEADER_COUNT_EXCEEDED', [f.code for f in r.findings])
    def test_json_no_raw(self):
        raw = request(b'Authorization: Bearer SECRET123\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n')
        r = SmugglingAuditor().analyze([SmugglingCapture(URL, raw)], scope_check=lambda u: True)
        self.assertNotIn('SECRET123', r.to_json())
    def test_origin_only(self):
        r = SmugglingAuditor().analyze([SmugglingCapture(URL+'?token=SECRET', request(b'Content-Length: 1\r\nContent-Length: 2\r\n'))], scope_check=lambda u: True)
        self.assertNotIn('SECRET', r.to_json())
    def test_capture_limit(self):
        r = SmugglingAuditor(SmugglingConfig(max_captures=1)).analyze([SmugglingCapture(URL, request()), SmugglingCapture(URL, request())], scope_check=lambda u: True)
        self.assertEqual(r.inspected, 1)
    def test_finding_limit(self):
        r = SmugglingAuditor(SmugglingConfig(max_findings=1)).analyze([SmugglingCapture(URL, request(b'Content-Length: 1\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n'))], scope_check=lambda u: True)
        self.assertEqual(len(r.findings), 1)
    def test_bad_config(self):
        with self.assertRaises(ValueError): SmugglingAuditor(SmugglingConfig(max_headers=0))
    def test_scope_required(self):
        with self.assertRaises(TypeError): SmugglingAuditor().analyze([], scope_check=None)
    def test_repeatable(self):
        cap = SmugglingCapture(URL, request(b'Content-Length: 1\r\nContent-Length: 2\r\n'))
        a = SmugglingAuditor()
        self.assertEqual(a.analyze([cap], scope_check=lambda u: True).to_json(), a.analyze([cap], scope_check=lambda u: True).to_json())

if __name__ == '__main__': unittest.main()

