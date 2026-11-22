import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from core.scope_engine import ScopeEngine, ScopeError
from core.confidence import ScopeStatus as S

def policy():
    return {'program':'Fixture','in_scope':[{'kind':'wildcard','value':'*.example.com','eligible':True,'max_severity':'medium'},{'kind':'host','value':'api.example.com','max_severity':'critical','eligible':True}], 'out_of_scope':[{'kind':'wildcard','value':'*.dev.example.com'}], 'excluded_assets':[{'kind':'host','value':'free.example.com'}], 'core_ineligible':['no-impact']}

class ScopeTests(unittest.TestCase):
    def setUp(self): self.engine=ScopeEngine.from_mapping(policy())
    def test_exact(self): self.assertEqual(self.engine.classify('https://api.example.com/').max_severity,'critical')
    def test_wildcard(self): self.assertEqual(self.engine.classify('https://a.b.example.com/').max_severity,'medium')
    def test_apex(self): self.assertEqual(self.engine.classify('https://example.com').status,S.PROHIBITED)
    def test_suffix(self): self.assertEqual(self.engine.classify('https://a.example.com.evil.org').status,S.PROHIBITED)
    def test_deny(self): self.assertEqual(self.engine.classify('https://a.dev.example.com').status,S.PROHIBITED)
    def test_excluded(self): self.assertFalse(self.engine.classify('https://free.example.com').eligible)
    def test_category(self): self.assertFalse(self.engine.classify('https://api.example.com',category='no-impact').eligible)
    def test_no_active_permission(self):
        d=self.engine.classify('https://api.example.com'); self.assertFalse(d.active_allowed); self.assertEqual(d.status,S.UNKNOWN)
    def test_malformed(self):
        for u in ['https://api.example.com@evil.org','https://api.example.com\\@evil.org','https://api.example.com:99999','https://api.example.com\n','https://api.example.com.','ftp://api.example.com']:
            with self.subTest(u=u): self.assertEqual(self.engine.classify(u).status,S.UNKNOWN)
    def test_duplicate(self):
        p=policy();p['in_scope']*=2
        with self.assertRaises(ScopeError): ScopeEngine.from_mapping(p)
    def test_unsupported(self):
        p=policy();p['out_of_scope'].append({'kind':'regex','value':'.*'})
        with self.assertRaises(ScopeError): ScopeEngine.from_mapping(p)
    def test_yaml_duplicates(self):
        with TemporaryDirectory() as d:
            p=Path(d)/'scope.yaml';p.write_text('program: A\nprogram: B\n')
            with self.assertRaises(ScopeError): ScopeEngine.from_yaml(p)
    def test_yaml_alias(self):
        with TemporaryDirectory() as d:
            p=Path(d)/'scope.yaml';p.write_text('program: &a A\nother: *a\n')
            with self.assertRaises(ScopeError): ScopeEngine.from_yaml(p)
    def test_url_exact(self):
        p=policy(); p['in_scope']=[{'kind':'url','value':'https://example.com/a'}]; e=ScopeEngine.from_mapping(p)
        self.assertIsNotNone(e.classify('https://example.com/a').rule); self.assertIsNone(e.classify('https://example.com/ab').rule)

