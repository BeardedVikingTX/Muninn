import tempfile
import unittest
import sqlite3
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from integrations.response_cache import ResponseCache, CacheError

class CacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'cache.db'; self.now=1000
        self.c=ResponseCache(self.path,clock=lambda:self.now,max_entries=2,max_bytes=100,max_entry_bytes=80)
    def key(self,i=1,p='nvd'):
        return self.c.key(p,'advisory',{'id':i},public=True)
    def put(self,i=1,v=None):
        self.c.put(self.key(i),v,ttl=10,public=True)
    def test_roundtrip_null(self):
        self.put(); self.assertIsNone(self.c.get(self.key()).value)
    def test_miss(self): self.assertIsNone(self.c.get(self.key()))
    def test_expiry(self):
        self.put(); self.now+=10; self.assertIsNone(self.c.get(self.key()))
    def test_provider(self): self.assertNotEqual(self.key(),self.key(p='other'))
    def test_canonical(self):
        k=lambda p:self.c.key('nvd','advisory',p,public=True)
        self.assertEqual(k({'a':1,'b':2}),k({'b':2,'a':1}))
    def test_private(self):
        with self.assertRaises(CacheError): self.c.put(self.key(),{},ttl=1)
    def test_secret(self):
        with self.assertRaises(CacheError): self.put(v={'api_key':'dummy'})
    def test_size(self):
        with self.assertRaises(CacheError): self.put(v='x'*100)
    def test_ttl(self):
        with self.assertRaises(CacheError): self.c.put(self.key(),{},ttl=float('nan'),public=True)
    def test_lru(self):
        self.put(1); self.now+=1; self.put(2); self.now+=1; self.c.get(self.key(1)); self.now+=1; self.put(3)
        self.assertIsNone(self.c.get(self.key(2))); self.assertIsNotNone(self.c.get(self.key(1)))
    def test_bytes(self):
        self.put(1,'x'*60); self.now+=1; self.put(2,'x'*60); self.assertEqual(self.c.status()['entries'],1)
    def test_restart(self):
        self.put(v={'x':1}); self.assertEqual(ResponseCache(self.path,clock=lambda:self.now).get(self.key()).value,{'x':1})
    def test_corruption(self):
        with sqlite3.connect(self.path) as db:
            self.put(); db.execute('UPDATE entries SET payload=?',(b'{}',))
        self.assertIsNone(self.c.get(self.key()))
    def test_rollback(self):
        self.put(); self.now-=1; self.assertIsNone(self.c.get(self.key()))
    def test_invalidate(self):
        self.put(); self.assertTrue(self.c.invalidate(self.key())); self.assertFalse(self.c.invalidate(self.key()))
    def test_concurrent(self):
        with ThreadPoolExecutor(max_workers=4) as pool: list(pool.map(self.put,range(20)))
        self.assertEqual(self.c.status()['entries'],2)
    def test_permissions(self):
        self.path.chmod(0o644)
        with self.assertRaises(CacheError): ResponseCache(self.path)
    def test_clear(self):
        self.put(); self.assertEqual(self.c.clear('nvd'),1)

