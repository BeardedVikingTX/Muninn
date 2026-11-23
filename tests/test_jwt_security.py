import base64
import hashlib
import hmac
import json
import unittest
from audit.jwt_security import JWTPolicy, JWTSecurityAuditor, discover_jwts, parse_jwt, verify_hmac


def enc(v):
    return base64.urlsafe_b64encode(json.dumps(v, separators=(',', ':')).encode()).decode().rstrip('=')


def token(header=None, claims=None, key=b'test-only-secret'):
    h = enc(header or {'alg':'HS256','typ':'JWT'})
    p = enc(claims or {'exp':2000,'iat':1000,'iss':'fixture','aud':'demo'})
    inp = f'{h}.{p}'
    sig = base64.urlsafe_b64encode(hmac.new(key, inp.encode(), hashlib.sha256).digest()).decode().rstrip('=')
    return inp + '.' + sig


class JWTTests(unittest.TestCase):
    def setUp(self):
        self.valid = token()
        self.auditor = JWTSecurityAuditor(JWTPolicy(max_lifetime_seconds=2000))

    def codes(self, t, **kwargs):
        return {f.code for f in self.auditor.analyze([t], now=1500, **kwargs).findings}

    def test_parse(self): self.assertEqual(parse_jwt(self.valid).claims['iss'], 'fixture')
    def test_signature(self): self.assertTrue(verify_hmac(self.valid, b'test-only-secret'))
    def test_wrong_key(self): self.assertFalse(verify_hmac(self.valid, b'wrong'))
    def test_no_key(self): self.assertFalse(verify_hmac(self.valid, b''))
    def test_no_hmac_allow(self): self.assertFalse(verify_hmac(self.valid, b'test-only-secret', allowed_algorithms=()))
    def test_discovery(self): self.assertEqual(discover_jwts('Bearer '+self.valid), [self.valid])
    def test_discovery_limit(self): self.assertEqual(discover_jwts(self.valid, max_tokens=0), [])
    def test_malformed(self): self.assertIn('MALFORMED_JWT', self.codes('not.jwt'))
    def test_unsigned(self): self.assertIn('UNSIGNED_JWT', self.codes(enc({'alg':'none'})+'.'+enc({'exp':2000})+'.'))
    def test_missing_signature(self): self.assertIn('MISSING_SIGNATURE', self.codes(enc({'alg':'HS256'})+'.'+enc({'exp':2000})+'.'))
    def test_unapproved(self): self.assertIn('UNAPPROVED_ALGORITHM', self.codes(token({'alg':'HS512'})))
    def test_jku(self): self.assertIn('REMOTE_KEY_REFERENCE', self.codes(token({'alg':'HS256','jku':'https://example.test/jwks'})))
    def test_x5u(self): self.assertIn('REMOTE_KEY_REFERENCE', self.codes(token({'alg':'HS256','x5u':'https://example.test/cert'})))
    def test_jwk(self): self.assertIn('EMBEDDED_JWK', self.codes(token({'alg':'HS256','jwk':{}})))
    def test_crit(self): self.assertIn('SPECIAL_HEADER', self.codes(token({'alg':'HS256','crit':['exp']})))
    def test_missing_exp(self): self.assertIn('MISSING_EXPIRATION', self.codes(token(claims={'iat':1000})))
    def test_expired(self): self.assertIn('EXPIRED', self.codes(token(claims={'exp':1000})))
    def test_invalid_exp(self): self.assertIn('INVALID_EXPIRATION', self.codes(token(claims={'exp':'tomorrow'})))
    def test_nbf(self): self.assertIn('NOT_YET_VALID', self.codes(token(claims={'exp':2000,'nbf':1700})))
    def test_invalid_nbf(self): self.assertIn('INVALID_NOT_BEFORE', self.codes(token(claims={'exp':2000,'nbf':'x'})))
    def test_future_iat(self): self.assertIn('FUTURE_ISSUED_AT', self.codes(token(claims={'exp':2000,'iat':1700})))
    def test_invalid_iat(self): self.assertIn('INVALID_ISSUED_AT', self.codes(token(claims={'exp':2000,'iat':'x'})))
    def test_bad_lifetime(self): self.assertIn('INVALID_LIFETIME', self.codes(token(claims={'exp':1000,'iat':1200})))
    def test_long_lifetime(self): self.assertIn('LONG_LIFETIME', self.codes(token(claims={'exp':9000,'iat':1000})))
    def test_issuer_mismatch(self):
        a = JWTSecurityAuditor(JWTPolicy(expected_issuer='other'))
        self.assertIn('ISSUER_MISMATCH', {f.code for f in a.analyze([self.valid], now=1500).findings})
    def test_audience_mismatch(self):
        a = JWTSecurityAuditor(JWTPolicy(expected_audience='other'))
        self.assertIn('AUDIENCE_MISMATCH', {f.code for f in a.analyze([self.valid], now=1500).findings})
    def test_valid_audience_list(self):
        a = JWTSecurityAuditor(JWTPolicy(expected_audience='demo', max_lifetime_seconds=2000))
        t = token(claims={'exp':2000,'iat':1000,'aud':['demo','other']})
        self.assertNotIn('AUDIENCE_MISMATCH', {f.code for f in a.analyze([t], now=1500).findings})
    def test_missing_audience(self):
        a = JWTSecurityAuditor(JWTPolicy(require_audience=True))
        self.assertIn('MISSING_AUDIENCE', {f.code for f in a.analyze([token(claims={'exp':2000})], now=1500).findings})
    def test_duplicate_token(self): self.assertEqual(len(self.auditor.analyze([self.valid,self.valid], now=1500).findings),0)
    def test_max_tokens(self): self.assertEqual(JWTSecurityAuditor(JWTPolicy(max_tokens=1)).analyze([self.valid,'bad'], now=1500).tokens_examined,1)
    def test_safe_summary(self): self.assertNotIn('fixture', json.dumps(parse_jwt(self.valid).safe_summary()))
    def test_json_redaction(self): self.assertNotIn(self.valid, self.auditor.analyze([self.valid], now=1500).to_json())
    def test_duplicate_claims_rejected(self):
        h=enc({'alg':'none'}); p=base64.urlsafe_b64encode(b'{"sub":"a","sub":"b"}').decode().rstrip('=')
        with self.assertRaises(ValueError): parse_jwt(h+'.'+p+'.')
    def test_bad_segment(self):
        with self.assertRaises(ValueError): parse_jwt('!!!.abc.def')

if __name__ == '__main__': unittest.main()

