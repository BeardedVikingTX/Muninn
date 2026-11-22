import json
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import Mock

from integrations.oast_client import (
    OASTClient, OASTConfig, OASTApproval, OASTDenied,
    OASTError, OASTProtocolError, OASTToken,
)

TOKEN = 'a' * 32

class Adapter:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []
    def request(self, **kwargs):
        self.calls.append(kwargs)
        if not self.responses:
            raise RuntimeError('no response')
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

def reply(value, status=200):
    return status, json.dumps(value).encode()

class OASTClientTests(unittest.TestCase):
    def setUp(self):
        self.now = [1000.0]
        self.adapter = Adapter([reply({'token': TOKEN}), reply({'events': [{'headers': {'Cookie': 'secret'}, 'body': 'secret'}]})])
        self.approval = OASTApproval('engagement-1', 'operator', 2000, True, True, True)
    def client(self, **kwargs):
        return OASTClient(config=kwargs.pop('config', OASTConfig(min_poll_interval_seconds=2)),
                          approval=kwargs.pop('approval', self.approval),
                          adapter=kwargs.pop('adapter', self.adapter),
                          api_key=kwargs.pop('api_key', 'K' * 32),
                          clock=lambda: self.now[0], monotonic=lambda: self.now[0], **kwargs)
    def test_register_and_check(self):
        c = self.client()
        token = c.register(correlation_id='probe-1')
        result = c.check(token)
        self.assertTrue(result.observed)
        self.assertEqual(result.event_count, 1)
        self.assertNotIn('secret', str(result.safe_summary()))
        self.assertNotIn(TOKEN, repr(token))
        self.assertEqual(len(self.adapter.calls), 2)
        self.assertEqual(self.adapter.calls[0]['method'], 'GET')
        self.assertTrue(self.adapter.calls[1]['url'].startswith('https://oast.beardedviking.org/check.php?'))
    def test_offline_default(self):
        with self.assertRaises(OASTDenied):
            self.client(adapter=None).register()
    def test_missing_approval(self):
        with self.assertRaises(OASTDenied):
            self.client(approval=None).register()
    def test_inactive_approval(self):
        a = OASTApproval('engagement-1','operator',2000,False,True,True)
        with self.assertRaises(OASTDenied): self.client(approval=a).register()
    def test_missing_oast_permission(self):
        a = OASTApproval('engagement-1','operator',2000,True,False,True)
        with self.assertRaises(OASTDenied): self.client(approval=a).register()
    def test_expired(self):
        self.now[0] = 2000
        with self.assertRaises(OASTDenied): self.client().register()
    def test_authentication_required(self):
        with self.assertRaises(OASTDenied): self.client(api_key='short').register()
    def test_read_permission_separate(self):
        a = OASTApproval('engagement-1','operator',2000,True,True,False)
        c = self.client(approval=a)
        t = c.register()
        with self.assertRaises(OASTDenied): c.check(t)
    def test_unregistered_token(self):
        c = self.client()
        with self.assertRaises(OASTDenied): c.check(OASTToken(TOKEN, 'unknown', 1000))
    def test_forged_token(self):
        c = self.client(); t = c.register()
        with self.assertRaises(OASTDenied): c.check(OASTToken('b'*32, t.correlation_id, 1000))
    def test_invalid_token_response(self):
        self.adapter.responses = [reply({'token':'../../bad'})]
        with self.assertRaises(OASTProtocolError): self.client().register()
    def test_duplicate_token(self):
        self.adapter.responses = [reply({'token':TOKEN}),reply({'token':TOKEN})]
        c = self.client(); c.register()
        with self.assertRaises(OASTProtocolError): c.register()
    def test_duplicate_correlation(self):
        c = self.client(); c.register(correlation_id='x')
        with self.assertRaises(OASTDenied): c.register(correlation_id='x')
    def test_bad_correlation(self):
        with self.assertRaises(OASTDenied): self.client().register(correlation_id='bad/../../')
    def test_token_limit(self):
        c = self.client(config=OASTConfig(max_tokens=1))
        c.register()
        with self.assertRaises(OASTDenied): c.register()
    def test_poll_limit(self):
        c = self.client(config=OASTConfig(max_polls=1,min_poll_interval_seconds=0))

