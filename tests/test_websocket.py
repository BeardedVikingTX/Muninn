import json
import unittest
from audit.websocket import WebSocketAuditor, WebSocketCapture, WebSocketMessage, WebSocketPolicy

URL = 'wss://example.test/ws'

def check(url):
    return url.startswith('wss://example.test/')

class WebSocketTests(unittest.TestCase):
    def scan(self, *captures, policy=None):
        return WebSocketAuditor(policy).analyze(captures, scope_check=check)

    def codes(self, *captures, policy=None):
        return {f.code for f in self.scan(*captures, policy=policy).findings}

    def test_empty(self): self.assertEqual(self.scan().captures_analyzed, 0)
    def test_scope_required(self):
        with self.assertRaises(TypeError): WebSocketAuditor().analyze([], scope_check=None)
    def test_scope_denied(self): self.assertEqual(self.scan(WebSocketCapture('wss://else.test/ws')).captures_skipped, 1)
    def test_invalid_url(self): self.assertEqual(self.scan(WebSocketCapture('not-url')).captures_skipped, 1)
    def test_credentials_in_url(self): self.assertIn('CREDENTIAL_IN_URL', self.codes(WebSocketCapture(URL+'?access_token=abc')))
    def test_token_in_url(self): self.assertIn('TOKEN_PATTERN_IN_URL', self.codes(WebSocketCapture(URL+'?x=ghp_abcdefghijklmnopqrstuvwxyz')))
    def test_safe_query(self): self.assertNotIn('CREDENTIAL_IN_URL', self.codes(WebSocketCapture(URL+'?page=1')))
    def test_plaintext(self):
        cap=WebSocketCapture('ws://example.test/ws')
        self.assertIn('INSECURE_TRANSPORT', {f.code for f in WebSocketAuditor().analyze([cap],scope_check=lambda _: True).findings})
    def test_tls_policy_disabled(self):
        cap=WebSocketCapture('ws://example.test/ws')
        self.assertNotIn('INSECURE_TRANSPORT', {f.code for f in WebSocketAuditor(WebSocketPolicy(require_tls=False)).analyze([cap],scope_check=lambda _: True).findings})
    def test_missing_accept(self): self.assertIn('MISSING_ACCEPT_HEADER', self.codes(WebSocketCapture(URL,101,{'Sec-WebSocket-Key':'abc'})))
    def test_good_accept(self): self.assertNotIn('MISSING_ACCEPT_HEADER', self.codes(WebSocketCapture(URL,101,{'Sec-WebSocket-Key':'abc'},{'Sec-WebSocket-Accept':'xyz'})))
    def test_unoffered_protocol(self): self.assertIn('UNOFFERED_SUBPROTOCOL', self.codes(WebSocketCapture(URL,101,{'Sec-WebSocket-Protocol':'chat'},{'Sec-WebSocket-Protocol':'admin'})))
    def test_offered_protocol(self): self.assertNotIn('UNOFFERED_SUBPROTOCOL', self.codes(WebSocketCapture(URL,101,{'Sec-WebSocket-Protocol':'chat, superchat'},{'Sec-WebSocket-Protocol':'superchat'})))
    def test_unauthenticated(self): self.assertIn('UNAUTHENTICATED_UPGRADE', self.codes(WebSocketCapture(URL,101,auth_required=True,unauthenticated_connection_accepted=True)))
    def test_no_unauth_without_upgrade(self): self.assertNotIn('UNAUTHENTICATED_UPGRADE', self.codes(WebSocketCapture(URL,403,auth_required=True,unauthenticated_connection_accepted=True)))
    def test_csws_hijack_fixture(self): self.assertIn('CROSS_ORIGIN_COOKIE_UPGRADE', self.codes(WebSocketCapture(URL,101,{'Origin':'https://evil.test','Cookie':'sid=abc'},cross_origin_test=True,origin_rejected=False)))
    def test_origin_allowlist(self): self.assertIn('UNEXPECTED_ORIGIN_UPGRADE', self.codes(WebSocketCapture(URL,101,{'Origin':'https://else.test','Cookie':'sid=abc'}),policy=WebSocketPolicy(allowed_origins=frozenset({'https://trusted.test'}))))
    def test_same_origin(self): self.assertNotIn('CROSS_ORIGIN_COOKIE_REVIEW', self.codes(WebSocketCapture(URL,101,{'Origin':'https://example.test','Cookie':'sid=abc'})))
    def test_missing_origin(self): self.assertIn('MISSING_ORIGIN_REVIEW', self.codes(WebSocketCapture(URL,101,{'Cookie':'sid=abc'})))
    def test_no_cookie_cross_origin(self): self.assertNotIn('CROSS_ORIGIN_COOKIE_REVIEW', self.codes(WebSocketCapture(URL,101,{'Origin':'https://else.test'})))
    def test_token_message(self): self.assertIn('TOKEN_IN_MESSAGE', self.codes(WebSocketCapture(URL,messages=(WebSocketMessage('server_to_client','Bearer abcdefghijklmnopqrstuvwxyz'),))))
    def test_sensitive_json(self): self.assertIn('SENSITIVE_FIELD_IN_SERVER_MESSAGE', self.codes(WebSocketCapture(URL,messages=(WebSocketMessage('server_to_client','{"password":"abc"}'),))))
    def test_client_sensitive_json(self): self.assertNotIn('SENSITIVE_FIELD_IN_SERVER_MESSAGE', self.codes(WebSocketCapture(URL,messages=(WebSocketMessage('client_to_server','{"password":"abc"}'),))))
    def test_nested_identifier(self): self.assertIn('OBJECT_REFERENCE_IN_CLIENT_MESSAGE', self.codes(WebSocketCapture(URL,messages=(WebSocketMessage('client_to_server','{"data":{"account_id":123}}'),))))
    def test_verified_disclosure(self): self.assertIn('VERIFIED_UNAUTHORIZED_DISCLOSURE', self.codes(WebSocketCapture(URL,messages=(WebSocketMessage('server_to_client','{}',expected_access=False,resource_disclosed=True,disclosure_verified=True),))))
    def test_unverified_disclosure(self): self.assertIn('POSSIBLE_UNAUTHORIZED_DISCLOSURE', self.codes(WebSocketCapture(URL,messages=(WebSocketMessage('server_to_client','{}',expected_access=False,resource_disclosed=True),))))
    def test_verified_action(self): self.assertIn('VERIFIED_UNAUTHORIZED_ACTION', self.codes(WebSocketCapture(URL,messages=(WebSocketMessage('client_to_server','{}',expected_access=False,action_committed=True,commit_verified=True),))))
    def test_unverified_action(self): self.assertIn('POSSIBLE_UNAUTHORIZED_ACTION', self.codes(WebSocketCapture(URL,messages=(WebSocketMessage('client_to_server','{}',expected_access=False,action_committed=True),))))
    def test_no_finding_for_authorized(self): self.assertNotIn('VERIFIED_UNAUTHORIZED_ACTION', self.codes(WebSocketCapture(URL,messages=(WebSocketMessage('client_to_server','{}',expected_access=True,action_committed=True,commit_verified=True),))))
    def test_no_finding_for_uncommitted(self): self.assertNotIn('VERIFIED_UNAUTHORIZED_ACTION', self.codes(WebSocketCapture(URL,messages=(WebSocketMessage('client_to_server','{}',expected_access=False,action_committed=False,commit_verified=True),))))
    def test_invalid_json(self): self.assertEqual(self.scan(WebSocketCapture(URL,messages=(WebSocketMessage('server_to_client','{bad'),))).messages_analyzed, 1)
    def test_message_size_limit(self):
        r=self.scan(WebSocketCapture(URL,messages=(WebSocketMessage('server_to_client','X'*10),)),policy=WebSocketPolicy(max_message_chars=5))
        self.assertEqual(r.messages_analyzed,0); self.assertTrue(r.truncated)
    def test_message_count_limit(self):
        r=self.scan(WebSocketCapture(URL,messages=(WebSocketMessage('server_to_client','{}'),)*3),policy=WebSocketPolicy(max_messages_per_capture=2))
        self.assertEqual(r.messages_analyzed,2); self.assertTrue(r.truncated)
    def test_capture_limit(self):
        r=self.scan(*[WebSocketCapture(URL) for _ in range(3)],policy=WebSocketPolicy(max_captures=2))
        self.assertEqual(r.captures_analyzed,2); self.assertTrue(r.truncated)
    def test_finding_limit(self):
        r=self.scan(WebSocketCapture(URL+'?token=x',messages=(WebSocketMessage('server_to_client','{"password":"a"}'),)),policy=WebSocketPolicy(max_findings=1))
        self.assertEqual(len(r.findings),1); self.assertTrue(r.truncated)
    def test_json_redaction(self):
        secret='ghp_abcdefghijklmnopqrstuvwxyz'
        r=self.scan(WebSocketCapture(URL+'?token='+secret,messages=(WebSocketMessage('server_to_client',secret),)))
        self.assertNotIn(secret,r.to_json()); self.assertNotIn('token=',r.to_json())
    def test_principal_redaction(self):
        r=self.scan(WebSocketCapture(URL,messages=(WebSocketMessage('server_to_client','{}',principal_id='private-person',resource_id='private-doc',expected_access=False,resource_disclosed=True),)))
        self.assertNotIn('private-person',r.to_json()); self.assertNotIn('private-doc',r.to_json())
    def test_deterministic(self):
        cap=WebSocketCapture(URL+'?token=abc')
        self.assertEqual(self.scan(cap).to_json(),self.scan(cap).to_json())
    def test_scope_callback_exception(self):
        r=WebSocketAuditor().analyze([WebSocketCapture(URL)],scope_check=lambda _: 1/0)
        self.assertEqual(r.captures_skipped,1)
    def test_bad_config(self):
        with self.assertRaises(ValueError): WebSocketPolicy(max_captures=0)
    def test_no_upgrade_origin(self): self.assertNotIn('CROSS_ORIGIN_COOKIE_UPGRADE',self.codes(WebSocketCapture(URL,403,{'Origin':'https://evil.test','Cookie':'x=y'},cross_origin_test=True,origin_rejected=False)))
    def test_nested_list(self): self.assertIn('SENSITIVE_FIELD_IN_SERVER_MESSAGE',self.codes(WebSocketCapture(URL,messages=(WebSocketMessage('server_to_client','[{"inner":{"api_key":"a"}}]'),))))
    def test_invalid_direction(self): self.assertEqual(self.scan(WebSocketCapture(URL,messages=(WebSocketMessage('unknown','{}'),))).messages_analyzed,0)

if __name__ == '__main__': unittest.main()

