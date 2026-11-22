import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
from integrations.credentials import Credentials
from integrations.quota_manager import QuotaManager, QuotaPolicy
from integrations.response_cache import ResponseCache
from integrations.api_client import APIClient, Operation

class APIClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        p = Path(self.tmp.name)
        self.creds = Credentials.load(environ={'GROQ_API_KEY':'synthetic-test-key','NVD_API_KEY':'synthetic-nvd-key'})
        self.quota = QuotaManager(p/'quota.db',{x:QuotaPolicy(10,100,2,lease_seconds=120) for x in ('groq','nvd')})
        self.cache = ResponseCache(p/'cache.db')
        self.client = APIClient(self.creds,self.quota,self.cache,online=True)
        self.mock = self.enterContext(patch('integrations.api_client.http.client.HTTPSConnection'))
        self.response = self.mock.return_value.getresponse.return_value
        self.response.status=200
        self.response.getheader.side_effect=lambda k,d='': {'Content-Type':'application/json'}.get(k,d)
        self.response.read.return_value=b'{"data": []}'
    def test_offline(self):
        self.client.online=False
        self.assertEqual(self.client.check('groq').status,'offline'); self.mock.assert_not_called()
    def test_probe(self):
        r=self.client.check('groq'); self.assertEqual(r.status,'ok'); self.assertIsNone(r.data)
        self.assertEqual(self.mock.call_args.args[:2],('api.groq.com',443))
        self.assertEqual(self.mock.return_value.request.call_args.kwargs['headers']['Authorization'],'Bearer synthetic-test-key')
    def test_unknown(self):
        self.assertEqual(self.client.check('unknown').status,'unknown_provider'); self.mock.assert_not_called()
    def test_missing(self):
        self.assertEqual(self.client.check('gemini').status,'not_configured'); self.mock.assert_not_called()
    def test_redirect(self):
        self.response.status=302; self.assertEqual(self.client.check('groq').status,'redirect_blocked'); self.assertEqual(self.mock.call_count,1)
    def test_auth(self):
        self.response.status=401; self.assertEqual(self.client.check('groq').status,'authentication_rejected')
    def test_forbidden(self):
        self.response.status=403; self.assertEqual(self.client.check('groq').status,'access_denied')
    def test_cooldown(self):
        self.response.status=429; self.assertEqual(self.client.check('groq').status,'rate_limited'); self.assertEqual(self.client.check('groq').status,'quota_denied'); self.assertEqual(self.mock.call_count,1)
    def test_cache(self):
        args=('nvd','cve_lookup'); kw={'parameters':{'cveId':'CVE-2021-44228'}}
        self.assertEqual(self.client.request(*args,**kw).status,'ok'); self.client.online=False
        self.assertTrue(self.client.request(*args,**kw).cached); self.assertEqual(self.mock.call_count,1)
    def test_payload_bound(self):
        self.client.max_bytes=5; self.assertEqual(self.client.check('groq').status,'response_too_large')
    def test_invalid_json(self):
        self.response.read.return_value=b'NaN'; self.assertEqual(self.client.check('groq').status,'invalid_json')
    def test_parameters(self):
        self.assertEqual(self.client.request('nvd','cve_lookup',parameters={'cveId':'https://example.org'}).status,'invalid_parameters'); self.mock.assert_not_called()
    def test_wrong_credential(self):
        with self.assertRaises(ValueError): Operation('groq','health','api.groq.com','/models','NVD_API_KEY')
    def test_timeout(self):
        self.mock.return_value.request.side_effect=TimeoutError(); self.assertEqual(self.client.check('groq').status,'timeout'); self.assertEqual(self.mock.call_count,1)
    def test_inventory(self):
        self.assertEqual(len(self.client.inventory()),23); self.mock.assert_not_called()

