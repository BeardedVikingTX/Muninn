import unittest
from integrations.recon_router import Asset, ReconError, ReconFact, ReconRouter, ProviderAdapter


class ReconRouterTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        def lookup(asset):
            self.calls.append(asset)
            return [ReconFact('asn', 'AS64500', 'public_intel')]
        self.adapter = ProviderAdapter('public_intel', frozenset({'domain', 'ip'}), lookup)
        self.router = ReconRouter(adapters=[self.adapter], online=True)
        self.asset = Asset('domain', 'Example.COM.')

    def test_domain_normalization(self):
        self.assertEqual(self.asset.value, 'example.com')

    def test_ip_normalization(self):
        self.assertEqual(Asset('ip', '2606:4700:4700::1111').value, '2606:4700:4700::1111')

    def test_private_ip_rejected(self):
        for ip in ('127.0.0.1', '10.0.0.1', '169.254.1.2', '::1', '192.168.0.1'):
            with self.subTest(ip=ip), self.assertRaises(ReconError): Asset('ip', ip)

    def test_url_origin_only(self):
        self.assertEqual(Asset('url', 'https://Example.com/').value, 'https://example.com')
        for url in ('http://example.com', 'https://example.com/private', 'https://example.com?token=abc', 'https://user:pass@example.com', 'https://example.com:444'):
            with self.subTest(url=url), self.assertRaises(ReconError): Asset('url', url)

    def test_invalid_domain(self):
        for domain in ('localhost', 'a..com', '-bad.com', '127.0.0.1', 'bad_domain.com'):
            with self.subTest(domain=domain), self.assertRaises(ReconError): Asset('domain', domain)

    def test_offline_default(self):
        r = ReconRouter(adapters=[self.adapter]); self.assertEqual(r.enrich(self.asset, 'public_intel', approved=True, permission=True).status, 'offline'); self.assertFalse(self.calls)

    def test_explicit_approval_required(self):
        self.assertEqual(self.router.enrich(self.asset, 'public_intel', permission=True).status, 'approval_required'); self.assertFalse(self.calls)

    def test_independent_permission_required(self):
        self.assertEqual(self.router.enrich(self.asset, 'public_intel', approved=True).status, 'approval_required'); self.assertFalse(self.calls)

    def test_success(self):
        r = self.router.enrich(self.asset, 'public_intel', approved=True, permission=True)
        self.assertEqual(r.status, 'ok'); self.assertEqual(r.facts[0].category, 'asn'); self.assertFalse(r.vulnerability_confirmed)

    def test_unknown_provider(self):
        self.assertEqual(self.router.enrich(self.asset, 'missing', approved=True, permission=True).status, 'provider_unavailable')

    def test_unsupported_kind(self):
        self.assertEqual(self.router.enrich(Asset('url', 'https://example.com'), 'public_intel', approved=True, permission=True).status, 'unsupported_asset')

    def test_duplicate_adapter(self):
        with self.assertRaises(ReconError): ReconRouter(adapters=[self.adapter, self.adapter])

    def test_inventory_dedup(self):
        self.assertEqual(self.router.inventory([self.asset, Asset('domain', 'example.com')]), (self.asset,))

    def test_inventory_bound(self):
        with self.assertRaises(ReconError): self.router.inventory([self.asset] * 129)

    def test_invalid_fact(self):
        with self.assertRaises(ReconError): ReconFact('invalid category', 'value', 'public_intel')

    def test_source_mismatch(self):
        a = ProviderAdapter('public_intel', frozenset({'domain'}), lambda _: [ReconFact('asn', 'AS1', 'other')])
        r = ReconRouter(adapters=[a], online=True).enrich(self.asset, 'public_intel', approved=True, permission=True)
        self.assertEqual(r.status, 'invalid_provider_data')

    def test_provider_error_redacted(self):
        def broken(_): raise RuntimeError('API-KEY-SECRET')
        a = ProviderAdapter('public_intel', frozenset({'domain'}), broken)
        r = ReconRouter(adapters=[a], online=True).enrich(self.asset, 'public_intel', approved=True, permission=True)
        self.assertEqual(r.status, 'provider_error'); self.assertNotIn('SECRET', repr(r))

    def test_result_bound(self):
        a = ProviderAdapter('public_intel', frozenset({'domain'}), lambda _: [ReconFact('asn', 'AS1', 'public_intel')] * 65)
        self.assertEqual(ReconRouter(adapters=[a], online=True).enrich(self.asset, 'public_intel', approved=True, permission=True).status, 'invalid_provider_data')

    def test_no_network_implicit(self):
        self.assertEqual(ReconRouter().status()['active_scanning'], False)

    def test_invalid_adapter(self):
        with self.assertRaises(ReconError): ProviderAdapter('bad name', frozenset({'domain'}), lambda _: [])

if __name__ == '__main__': unittest.main()

