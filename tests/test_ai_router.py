import unittest
import json
from integrations.ai_router import AIRouter, Route, Observation, RouterError, Unavailable, parse_advisory

class Fake:
    def __init__(self, error=None): self.calls=0; self.error=error
    def analyze(self, route, **kwargs):
        self.calls+=1
        if self.error: raise self.error
        return json.dumps(dict(summary='Review configuration',references=['a'],remediation='Apply least privilege'))

class RouterTests(unittest.TestCase):
    def setUp(self):
        self.fake=Fake(); self.obs=[Observation('a','Synthetic configuration review')]; self.routes=[Route('groq','test'),Route('gemini','test')]
    def router(self, **kw): return AIRouter(self.routes,{'groq':self.fake},**kw)
    def test_offline(self): self.assertEqual(self.router().analyze(self.obs).status,'offline'); self.assertEqual(self.fake.calls,0)
    def test_approval(self): self.assertEqual(self.router(online=True).analyze(self.obs).status,'approval_required'); self.assertEqual(self.fake.calls,0)
    def test_success(self): self.assertEqual(self.router(online=True).analyze(self.obs,approved=True).advisory.references,('a',))
    def test_secret(self):
        with self.assertRaises(RouterError): Observation('a','Authorization: example')
    def test_duplicate(self):
        with self.assertRaises(RouterError): self.router(online=True).analyze(self.obs*2,approved=True)
    def test_no_adapter(self): self.assertEqual(AIRouter(self.routes,online=True).analyze(self.obs,approved=True).status,'no_adapter')
    def test_fallback(self):
        first=Fake(Unavailable()); r=AIRouter(self.routes,{'groq':first,'gemini':self.fake},online=True,max_attempts=2)
        self.assertEqual(r.analyze(self.obs,approved=True).provider,'gemini')
    def test_attempt_limit(self):
        r=AIRouter(self.routes,{'groq':Fake(Unavailable()),'gemini':self.fake},online=True)
        self.assertEqual(r.analyze(self.obs,approved=True).status,'unavailable'); self.assertEqual(self.fake.calls,0)
    def test_unknown_reference(self):
        with self.assertRaises(RouterError): parse_advisory('{"summary":"x","references":["b"],"remediation":"y"}',{'a'})
    def test_extra_field(self):
        with self.assertRaises(RouterError): parse_advisory('{"summary":"x","references":["a"],"remediation":"y","validated":true}',{'a'})
    def test_duplicate_json(self):
        with self.assertRaises(RouterError): parse_advisory('{"summary":"x","summary":"y","references":["a"],"remediation":"y"}',{'a'})
    def test_error_sanitized(self):
        self.fake.error=ValueError('secret value'); result=self.router(online=True).analyze(self.obs,approved=True); self.assertEqual(result.status,'adapter_error'); self.assertNotIn('secret value',repr(result))

