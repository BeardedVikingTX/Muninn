import unittest
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from integrations.threat_intel import (Indicator, ThreatRecord, ThreatIntel,
    ThreatIntelError, ThreatAdapter, normalize_indicator)

NOW = datetime(2026, 11, 22, tzinfo=timezone.utc)

def rec(value='8.8.8.8', source='feed'):
    return ThreatRecord(Indicator('ip', value), source, '2026-11-20T00:00:00Z',
                        '2026-11-24T00:00:00Z', 'suspicious')

class ThreatIntelTests(unittest.TestCase):
    def make(self, **kw):
        return ThreatIntel(clock=lambda: NOW, **kw)
    def test_ip_normalize(self):
        self.assertEqual(Indicator('ip','8.8.8.8').value,'8.8.8.8')
    def test_private_ip_rejected(self):
        for ip in ('127.0.0.1','10.0.0.1','::1','169.254.1.2'):
            with self.subTest(ip=ip), self.assertRaises(ThreatIntelError): Indicator('ip',ip)
    def test_domain_normalize(self):
        self.assertEqual(Indicator('domain','Example.COM.').value,'example.com')
    def test_internal_domain_rejected(self):
        with self.assertRaises(ThreatIntelError): Indicator('domain','server.local')
    def test_sha256(self):
        self.assertEqual(Indicator('sha256','A'*64).value,'a'*64)
    def test_bad_sha256(self):
        with self.assertRaises(ThreatIntelError): Indicator('sha256','a'*63)
    def test_url(self):
        self.assertEqual(Indicator('url','https://Example.COM/a').value,'https://example.com/a')
    def test_url_userinfo_rejected(self):
        with self.assertRaises(ThreatIntelError): Indicator('url','https://user:pass@example.com/')
    def test_url_http_rejected(self):
        with self.assertRaises(ThreatIntelError): Indicator('url','http://example.com/')
    def test_ingest_lookup(self):
        t=self.make(); t.ingest([rec()]); m=t.lookup(Indicator('ip','8.8.8.8'))
        self.assertEqual(m.status,'matched'); self.assertFalse(m.confirmed_compromise)
    def test_miss(self):
        self.assertEqual(self.make().lookup(Indicator('ip','8.8.8.8')).status,'no_current_match')
    def test_expired(self):
        t=self.make(); t.ingest([ThreatRecord(Indicator('ip','8.8.8.8'),'feed','2026-11-01T00:00:00Z','2026-11-02T00:00:00Z','spam')]); self.assertEqual(t.status()['records'],0)
    def test_future_observation(self):
        t=self.make(); t.ingest([ThreatRecord(Indicator('ip','8.8.8.8'),'feed','2026-11-23T00:00:00Z','2026-11-24T00:00:00Z','spam')]); self.assertEqual(t.lookup(Indicator('ip','8.8.8.8')).status,'no_current_match')
    def test_dedupe(self):
        t=self.make(); t.ingest([rec(),rec()]); self.assertEqual(t.status()['records'],1)
    def test_capacity_atomic(self):
        t=self.make(max_records=1); t.ingest([rec()]);
        with self.assertRaises(ThreatIntelError): t.ingest([rec('1.1.1.1')])
        self.assertEqual(t.status()['records'],1)
    def test_invalid_window(self):
        with self.assertRaises(ThreatIntelError): ThreatRecord(Indicator('ip','8.8.8.8'),'feed','2026-11-24T00:00:00Z','2026-11-20T00:00:00Z','spam')
    def test_offline(self):
        a=ThreatAdapter('feed',frozenset({'ip'}),lambda _: [rec()]); t=self.make(adapters=[a]); self.assertEqual(t.enrich(Indicator('ip','8.8.8.8'),'feed',approved=True,permission=True).status,'offline')
    def test_approval(self):
        a=ThreatAdapter('feed',frozenset({'ip'}),lambda _: [rec()]); t=self.make(adapters=[a],online=True); self.assertEqual(t.enrich(Indicator('ip','8.8.8.8'),'feed').status,'approval_required')
    def test_enrichment(self):
        a=ThreatAdapter('feed',frozenset({'ip'}),lambda _: [rec()]); t=self.make(adapters=[a],online=True); self.assertEqual(t.enrich(Indicator('ip','8.8.8.8'),'feed',approved=True,permission=True).status,'ok')
    def test_mismatch(self):
        a=ThreatAdapter('feed',frozenset({'ip'}),lambda _: [rec('1.1.1.1')]); t=self.make(adapters=[a],online=True); self.assertEqual(t.enrich(Indicator('ip','8.8.8.8'),'feed',approved=True,permission=True).status,'provider_mismatch')
    def test_error_sanitized(self):
        def bad(_): raise RuntimeError('secret')
        a=ThreatAdapter('feed',frozenset({'ip'}),bad); t=self.make(adapters=[a],online=True); self.assertEqual(t.enrich(Indicator('ip','8.8.8.8'),'feed',approved=True,permission=True).status,'provider_error')
    def test_threaded(self):
        t=self.make()
        with ThreadPoolExecutor(max_workers=8) as pool: list(pool.map(lambda _: t.ingest([rec()]), range(40)))
        self.assertEqual(t.status()['records'],1)
    def test_fingerprint(self):
        t=self.make(); i=Indicator('ip','8.8.8.8'); self.assertEqual(t.fingerprint(i),t.fingerprint(i)); self.assertEqual(len(t.fingerprint(i)),64)

if __name__=='__main__': unittest.main()

