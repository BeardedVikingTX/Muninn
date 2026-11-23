import json
import unittest
from audit.sensitive_data_exposure import SensitiveDataExposureAuditor, ExposureCapture

URL = 'https://example.test/api/profile'
def scan(*caps, **kwargs):
    return SensitiveDataExposureAuditor(**kwargs).analyze(caps, scope_check=lambda u: u.startswith('https://example.test/'))
def kinds(report):
    return {f.category for f in report.findings}

class SensitiveDataTests(unittest.TestCase):
    def test_empty(self): self.assertEqual(scan().examined, 0)
    def test_scope(self): self.assertEqual(scan(ExposureCapture('https://other.test/x', response_body='AKIA'+'A'*16)).skipped_out_of_scope, 1)
    def test_invalid_scheme(self): self.assertEqual(scan(ExposureCapture('file:///etc/passwd')).skipped_out_of_scope, 1)
    def test_aws(self): self.assertIn('aws_access_key', kinds(scan(ExposureCapture(URL, response_body='AKIA'+'A'*16))))
    def test_github(self): self.assertIn('github_token', kinds(scan(ExposureCapture(URL, response_body='ghp_'+'a'*36))))
    def test_fine_grained(self): self.assertIn('github_fine_grained_token', kinds(scan(ExposureCapture(URL, response_body='github_pat_'+'a'*30))))
    def test_slack(self): self.assertIn('slack_token', kinds(scan(ExposureCapture(URL, response_body='xoxb-'+'a'*20))))
    def test_stripe(self): self.assertIn('stripe_secret', kinds(scan(ExposureCapture(URL, response_body='sk_live_'+'a'*20))))
    def test_private_key(self): self.assertIn('private_key', kinds(scan(ExposureCapture(URL, response_body='-----BEGIN PRIVATE KEY-----'))))
    def test_jwt(self): self.assertIn('jwt_like', kinds(scan(ExposureCapture(URL, response_body='eyJabcdefgh.eyJabcdefgh.signature'))))
    def test_assignment(self): self.assertIn('credential_assignment', kinds(scan(ExposureCapture(URL, response_body='password="realistic-secret-value"'))))
    def test_placeholder(self): self.assertNotIn('credential_assignment', kinds(scan(ExposureCapture(URL, response_body='password="placeholder-password"'))))
    def test_query(self): self.assertIn('sensitive_query_parameter', kinds(scan(ExposureCapture(URL+'?access_token=secret'))))
    def test_no_query_value(self): self.assertNotIn('secret', scan(ExposureCapture(URL+'?access_token=secret')).to_json())
    def test_http_header(self):
        report = SensitiveDataExposureAuditor().analyze([ExposureCapture('http://example.test/', request_headers={'Authorization':'Bearer secret'})], scope_check=lambda _: True)
        self.assertIn('credential_over_http', kinds(report))
    def test_email(self): self.assertIn('email_address', kinds(scan(ExposureCapture(URL, response_body='hello@example.test'))))
    def test_ssn(self): self.assertIn('us_ssn_like', kinds(scan(ExposureCapture(URL, response_body='123-45-6789'))))
    def test_python_traceback(self): self.assertIn('python_traceback', kinds(scan(ExposureCapture(URL, response_body='Traceback (most recent call last):'))))
    def test_sql_error(self): self.assertIn('sql_error', kinds(scan(ExposureCapture(URL, response_body='SQLiteException'))))
    def test_env(self): self.assertIn('env_configuration', kinds(scan(ExposureCapture(URL, response_body='DATABASE_URL=postgres://example'))))
    def test_git(self): self.assertIn('git_configuration', kinds(scan(ExposureCapture(URL, response_body='[core]\nrepositoryformatversion = 0'))))
    def test_cache(self): self.assertIn('sensitive_shared_cache', kinds(scan(ExposureCapture(URL, response_body='AKIA'+'A'*16, response_headers={'Cache-Control':'public, max-age=600'}))))
    def test_cors(self): self.assertIn('wildcard_cors_sensitive_response', kinds(scan(ExposureCapture(URL, response_body='AKIA'+'A'*16, response_headers={'Access-Control-Allow-Origin':'*'}))))
    def test_verified(self): self.assertIn('verified_unauthorized_disclosure', kinds(scan(ExposureCapture(URL, unauthorized_access_verified=True, verified_sensitive_resource=True))))
    def test_not_verified(self): self.assertNotIn('verified_unauthorized_disclosure', kinds(scan(ExposureCapture(URL, unauthorized_access_verified=True))))
    def test_no_raw_secret(self):
        token='ghp_'+'a'*36
        self.assertNotIn(token, scan(ExposureCapture(URL, response_body=token)).to_json())
    def test_no_query_path(self): self.assertNotIn('access_token', scan(ExposureCapture(URL+'?access_token=secret')).findings[0].location)
    def test_dedupe(self): self.assertEqual(len(scan(ExposureCapture(URL, response_body='AKIA'+'A'*16), ExposureCapture(URL, response_body='AKIA'+'A'*16)).findings), 1)
    def test_limit(self): self.assertTrue(scan(ExposureCapture(URL), ExposureCapture(URL), max_captures=1).truncated)
    def test_body_limit(self): self.assertTrue(scan(ExposureCapture(URL, response_body='a'*100), max_body_chars=10).truncated)
    def test_finding_limit(self): self.assertTrue(scan(ExposureCapture(URL, response_body='AKIA'+'A'*16+' ghp_'+'a'*36), max_findings=1).truncated)
    def test_bad_limits(self):
        with self.assertRaises(ValueError): SensitiveDataExposureAuditor(max_captures=0)
    def test_missing_scope(self):
        with self.assertRaises(TypeError): SensitiveDataExposureAuditor().analyze([], scope_check=None)
    def test_invalid_capture(self):
        with self.assertRaises(TypeError): scan('not-a-capture')
    def test_determinism(self):
        cap=ExposureCapture(URL, response_body='AKIA'+'A'*16)
        self.assertEqual(scan(cap).to_json(), scan(cap).to_json())
    def test_json(self): self.assertEqual(json.loads(scan().to_json())['findings'], [])

if __name__ == '__main__': unittest.main()

