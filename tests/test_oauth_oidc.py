import unittest
from audit.oauth_oidc import OAuthCapture, OAuthOIDCAuditor

BASE='https://app.example.test/oauth/authorize'

def run(captures, **kw):
    return OAuthOIDCAuditor(**kw).analyze(captures, scope_check=lambda u: u.startswith('https://app.example.test/'))

def codes(capture):
    return {f.code for f in run([capture]).findings}

class OAuthTests(unittest.TestCase):
    def test_missing_state(self):
        self.assertIn('MISSING_STATE', codes(OAuthCapture(BASE+'?response_type=code')))
    def test_state_present(self):
        self.assertNotIn('MISSING_STATE', codes(OAuthCapture(BASE+'?state=abc')))
    def test_missing_pkce(self):
        self.assertIn('MISSING_PKCE', codes(OAuthCapture(BASE+'?state=a', pkce_required=True)))
    def test_weak_pkce(self):
        self.assertIn('WEAK_PKCE_METHOD', codes(OAuthCapture(BASE+'?state=a&code_challenge=abc', pkce_required=True)))
    def test_good_pkce(self):
        self.assertNotIn('WEAK_PKCE_METHOD', codes(OAuthCapture(BASE+'?state=a&code_challenge=abc&code_challenge_method=S256', pkce_required=True)))
    def test_implicit(self):
        self.assertIn('FRONT_CHANNEL_TOKEN', codes(OAuthCapture(BASE+'?state=a&response_type=token')))
    def test_oidc_nonce(self):
        self.assertIn('MISSING_OIDC_NONCE', codes(OAuthCapture(BASE+'?state=a&scope=openid&response_type=id_token', oidc_required=True)))
    def test_code_flow_nonce_not_required(self):
        self.assertNotIn('MISSING_OIDC_NONCE', codes(OAuthCapture(BASE+'?state=a&scope=openid&response_type=code', oidc_required=True)))
    def test_http_redirect(self):
        self.assertIn('HTTP_REDIRECT_URI', codes(OAuthCapture(BASE+'?state=a&redirect_uri=http%3A%2F%2Fevil.test%2Fcb')))
    def test_loopback_redirect(self):
        self.assertNotIn('HTTP_REDIRECT_URI', codes(OAuthCapture(BASE+'?state=a&redirect_uri=http%3A%2F%2Flocalhost%2Fcb')))
    def test_callback_mismatch(self):
        self.assertIn('STATE_MISMATCH', codes(OAuthCapture('https://app.example.test/cb?code=abc&state=x',phase='callback',expected_state='y')))
    def test_callback_state_match(self):
        self.assertNotIn('STATE_MISMATCH', codes(OAuthCapture('https://app.example.test/cb?code=abc&state=x',phase='callback',expected_state='x')))
    def test_callback_no_state(self):
        self.assertIn('CALLBACK_MISSING_STATE', codes(OAuthCapture('https://app.example.test/cb?code=abc',phase='callback')))
    def test_query_token(self):
        self.assertIn('SENSITIVE_QUERY_PARAMETER', codes(OAuthCapture(BASE+'?access_token=secret')))
    def test_http(self):
        r=OAuthOIDCAuditor().analyze([OAuthCapture('http://app.example.test/cb',phase='callback')],scope_check=lambda _:True)
        self.assertIn('INSECURE_TRANSPORT', {f.code for f in r.findings})
    def test_token_get(self):
        self.assertIn('TOKEN_ENDPOINT_GET', codes(OAuthCapture('https://app.example.test/token',phase='token')))
    def test_token_missing_verifier(self):
        self.assertIn('MISSING_CODE_VERIFIER', codes(OAuthCapture('https://app.example.test/token',method='POST',phase='token',pkce_required=True,request_headers={'Content-Type':'application/x-www-form-urlencoded'},request_body='grant_type=authorization_code&code=abc')))
    def test_token_cache(self):
        self.assertIn('TOKEN_RESPONSE_CACHE_POLICY', codes(OAuthCapture('https://app.example.test/token',method='POST',phase='token',response_body='{"access_token":"abc"}')))
    def test_token_no_store(self):
        self.assertNotIn('TOKEN_RESPONSE_CACHE_POLICY', codes(OAuthCapture('https://app.example.test/token',method='POST',phase='token',response_body='{"access_token":"abc"}',response_headers={'Cache-Control':'no-store'})))
    def test_metadata_pkce(self):
        self.assertIn('METADATA_NO_S256', codes(OAuthCapture('https://app.example.test/.well-known/openid-configuration',phase='metadata',response_body='{"code_challenge_methods_supported":["plain"]}')))
    def test_metadata_none(self):
        self.assertIn('METADATA_UNSIGNED_ID_TOKEN', codes(OAuthCapture('https://app.example.test/.well-known/openid-configuration',phase='metadata',response_body='{"id_token_signing_alg_values_supported":["none"]}')))
    def test_verified_issuer(self):
        self.assertIn('OIDC_ISSUER_MISMATCH', codes(OAuthCapture(BASE,phase='callback',trusted_token_claims={'iss':'other'},verified_token_signature=True,expected_issuer='expected')))
    def test_verified_audience(self):
        self.assertIn('OIDC_AUDIENCE_MISMATCH', codes(OAuthCapture(BASE,phase='callback',trusted_token_claims={'aud':['other']},verified_token_signature=True,expected_audience='expected')))
    def test_verified_nonce(self):
        self.assertIn('OIDC_NONCE_MISMATCH', codes(OAuthCapture(BASE,phase='callback',trusted_token_claims={'nonce':'bad'},verified_token_signature=True,expected_nonce='good')))
    def test_unverified_claims(self):
        c=codes(OAuthCapture(BASE,phase='callback',trusted_token_claims={'iss':'bad'},expected_issuer='good'))
        self.assertIn('UNVERIFIED_ID_TOKEN_CLAIMS',c)
        self.assertNotIn('OIDC_ISSUER_MISMATCH',c)
    def test_scope(self):
        r=run([OAuthCapture('https://elsewhere.test/?access_token=secret')]); self.assertEqual(r.skipped_out_of_scope,1)
    def test_no_secret_in_report(self):
        r=run([OAuthCapture(BASE+'?access_token=supersecret&state=abc',transaction_id='verysecret')]); self.assertNotIn('supersecret',r.to_json()); self.assertNotIn('verysecret',r.to_json())
    def test_dedup(self):
        r=run([OAuthCapture(BASE),OAuthCapture(BASE)]); self.assertEqual(len([f for f in r.findings if f.code=='MISSING_STATE']),1)
    def test_limit(self):
        r=run([OAuthCapture(BASE)]*4,max_captures=2); self.assertEqual(r.analyzed,2)
    def test_limit_validation(self):
        with self.assertRaises(ValueError): OAuthOIDCAuditor(max_findings=0)
    def test_callback_redirect(self):
        self.assertIn('INSECURE_CALLBACK_REDIRECT',codes(OAuthCapture('https://app.example.test/cb?state=a',phase='callback',response_headers={'Location':'http://example.org/next'})))
    def test_form_body(self):
        self.assertNotIn('MISSING_STATE',codes(OAuthCapture(BASE,method='POST',request_headers={'Content-Type':'application/x-www-form-urlencoded'},request_body='state=abc')))
    def test_json_body(self):
        self.assertNotIn('MISSING_STATE',codes(OAuthCapture(BASE,method='POST',request_headers={'Content-Type':'application/json'},request_body='{"state":"abc"}')))

if __name__=='__main__': unittest.main()

