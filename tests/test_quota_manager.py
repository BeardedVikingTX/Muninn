import tempfile
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from integrations.quota_manager import QuotaManager, QuotaPolicy

class QuotaTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'quota.db'; self.now=86400+100
        self.p={'demo':QuotaPolicy(2,3,1,100,10)}
        self.q=QuotaManager(self.path,self.p,clock=lambda:self.now)
    def test_unknown(self): self.assertFalse(self.q.reserve('other').allowed)
    def test_concurrency(self):
        self.assertTrue(self.q.reserve('demo').allowed)
        self.assertEqual(self.q.reserve('demo').reason,'concurrency')
    def test_finish(self):
        d=self.q.reserve('demo'); self.assertTrue(self.q.finish(d.lease_id)); self.assertFalse(self.q.finish(d.lease_id))
        self.assertTrue(self.q.reserve('demo').allowed)
    def test_minute(self):
        for _ in range(2): self.q.finish(self.q.reserve('demo').lease_id)
        self.assertEqual(self.q.reserve('demo').reason,'minute_requests'); self.now+=60
        self.assertTrue(self.q.reserve('demo').allowed)
    def test_daily(self):
        for _ in range(3):
            self.q.finish(self.q.reserve('demo').lease_id); self.now+=60
        self.assertEqual(self.q.reserve('demo').reason,'daily_requests'); self.now=172800
        self.assertTrue(self.q.reserve('demo').allowed)
    def test_tokens(self):
        d=self.q.reserve('demo',estimated_tokens=90); self.q.finish(d.lease_id,actual_tokens=110)
        self.assertEqual(self.q.reserve('demo',estimated_tokens=1).reason,'daily_tokens')
    def test_no_refund(self):
        d=self.q.reserve('demo',estimated_tokens=90); self.q.finish(d.lease_id,actual_tokens=1)
        self.assertEqual(self.q.status('demo')['daily_tokens'],90)
    def test_cooldown(self):
        self.q.cooldown('demo',30); self.q.cooldown('demo',5)
        self.assertEqual(self.q.reserve('demo').retry_after,30); self.now+=30
        self.assertTrue(self.q.reserve('demo').allowed)
    def test_expiry(self):
        self.q.reserve('demo'); self.now+=10; self.assertTrue(self.q.reserve('demo').allowed)
    def test_persistence(self):
        self.q.reserve('demo'); other=QuotaManager(self.path,self.p,clock=lambda:self.now)
        self.assertEqual(other.status('demo')['daily_requests'],1)
        self.assertFalse(other.reserve('demo').allowed)
    def test_threads(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(lambda _:self.q.reserve('demo'),range(16)))
        self.assertEqual(sum(x.allowed for x in results),1)
    def test_clock_rollback(self):
        self.q.reserve('demo'); self.now-=1
        with self.assertRaises(RuntimeError): self.q.reserve('demo')
    def test_bad_tokens(self):
        with self.assertRaises(ValueError): self.q.reserve('demo',estimated_tokens=-1)
    def test_prune(self):
        self.q.reserve('demo'); self.now=172800; self.assertEqual(self.q.prune(),1)
    def test_disabled(self):
        q=QuotaManager(self.path,{'off':QuotaPolicy(0,1,1)},clock=lambda:self.now)
        self.assertEqual(q.reserve('off').reason,'disabled')

if __name__=='__main__': unittest.main()

