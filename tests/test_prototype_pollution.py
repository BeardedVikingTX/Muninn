import json
import unittest
from audit.prototype_pollution import (PollutionCapture, PollutionConfig,
    PrototypePollutionAuditor, classify_path, split_property_path, walk_json)

URL = 'https://test.example/api/update'

def scan(*captures, config=None, scope=lambda _: True):
    return PrototypePollutionAuditor(config).analyze(captures, scope_check=scope)

class PrototypePollutionTests(unittest.TestCase):
    def test_dot_path(self):
        self.assertEqual(split_property_path('a.__proto__.flag'), ('a', '__proto__', 'flag'))
    def test_bracket_path(self):
        self.assertEqual(split_property_path('a[constructor][prototype][flag]'), ('a','constructor','prototype','flag'))
    def test_quoted_bracket(self):
        self.assertEqual(split_property_path("a['__proto__'][flag]"), ('a','__proto__','flag'))
    def test_encoded_path(self):
        self.assertEqual(split_property_path('%255f%255fproto%255f%255f.flag'), ('__proto__','flag'))
    def test_proto_chain(self):
        self.assertEqual(classify_path(('__proto__','flag')), 'proto-chain')
    def test_constructor_chain(self):
        self.assertEqual(classify_path(('constructor','prototype','flag')), 'constructor-prototype-chain')
    def test_standalone_proto_not_flagged(self):
        self.assertIsNone(classify_path(('__proto__',)))
    def test_standalone_constructor_not_flagged(self):
        self.assertIsNone(classify_path(('constructor','name')))
    def test_nested_json(self):
        paths = walk_json({'a': {'__proto__': {'flag': 1}}}, max_nodes=100, max_depth=10)
        self.assertTrue(paths)
    def test_json_list(self):
        self.assertTrue(walk_json([{'constructor': {'prototype': {'x': True}}}], max_nodes=100, max_depth=10))
    def test_node_limit(self):
        with self.assertRaises(ValueError):
            walk_json([1,2,3], max_nodes=2, max_depth=10)
    def test_depth_limit(self):
        with self.assertRaises(ValueError):
            walk_json({'a': {'b': 1}}, max_nodes=100, max_depth=1)
    def test_query_detection(self):
        r = scan(PollutionCapture(URL+'?__proto__[flag]=1'))
        self.assertEqual(len(r.findings), 1)
    def test_form_detection(self):
        r = scan(PollutionCapture(URL, request_body='constructor[prototype][flag]=1', content_type='application/x-www-form-urlencoded'))
        self.assertEqual(len(r.findings), 1)
    def test_json_body_detection(self):
        r = scan(PollutionCapture(URL, request_body='{"__proto__":{"flag":true}}', content_type='application/json'))
        self.assertTrue(r.findings)
    def test_explicit_json_detection(self):
        r = scan(PollutionCapture(URL, request_json={'__proto__': {'flag': True}}))
        self.assertTrue(r.findings)
    def test_harmless_json(self):
        self.assertFalse(scan(PollutionCapture(URL, request_json={'name':'safe'})).findings)
    def test_sink_detection(self):
        r = scan(PollutionCapture(URL, javascript_source='Object.assign(target, input);'))
        self.assertEqual(r.findings[0].category, 'potential-merge-sink')
    def test_sink_not_proof(self):
        r = scan(PollutionCapture(URL, javascript_source='_.merge({}, input)'))
        self.assertEqual(r.findings[0].confidence, 'low')
    def test_verified_fixture(self):
        r = scan(PollutionCapture(URL, request_json={'__proto__':{'flag':1}}, pollution_verified=True))
        self.assertEqual(r.findings[0].confidence, 'high')
    def test_verified_flag_does_not_upgrade_sink(self):
        r = scan(PollutionCapture(URL, javascript_source='Object.assign(a,b)', pollution_verified=True))
        self.assertEqual(r.findings[0].confidence, 'low')
    def test_out_of_scope(self):
        r = scan(PollutionCapture(URL+'?__proto__.x=1'), scope=lambda _: False)
        self.assertEqual((r.captures_analyzed,r.captures_skipped), (0,1))
    def test_scope_error_fails_closed(self):
        def fail(_): raise RuntimeError('scope error')
        self.assertFalse(scan(PollutionCapture(URL+'?__proto__.x=1'), scope=fail).findings)
    def test_scope_callback_required(self):
        with self.assertRaises(TypeError):
            PrototypePollutionAuditor().analyze([], scope_check=None)
    def test_duplicate_findings(self):
        cap = PollutionCapture(URL+'?__proto__.x=1')
        self.assertEqual(len(scan(cap,cap).findings),1)
    def test_max_findings(self):
        config = PollutionConfig(max_findings=1)
        r = scan(PollutionCapture(URL, javascript_source='Object.assign(a,b); _.merge(a,b)'), config=config)
        self.assertEqual(len(r.findings),1)
    def test_max_captures(self):
        r = scan(PollutionCapture(URL), PollutionCapture(URL), config=PollutionConfig(max_captures=1))
        self.assertEqual(r.captures_analyzed,1)
    def test_body_limit(self):
        r = scan(PollutionCapture(URL, request_body='__proto__.x=1', content_type='application/x-www-form-urlencoded'), config=PollutionConfig(max_body_bytes=3))
        self.assertFalse(r.findings)
    def test_source_limit(self):
        r = scan(PollutionCapture(URL, javascript_source='Object.assign(a,b)'), config=PollutionConfig(max_source_bytes=3))
        self.assertFalse(r.findings)
    def test_sensitive_value_not_reported(self):
        secret='SECRET-PRIVATE-DO-NOT-LOG'
        r=scan(PollutionCapture(URL+'?__proto__.flag='+secret, request_json={'__proto__':{'flag':secret}}))
        self.assertNotIn(secret,r.to_json())
    def test_query_values_not_reported(self):
        self.assertNotIn('supersecret', scan(PollutionCapture(URL+'?__proto__.x=supersecret')).to_json())
    def test_deterministic_json(self):
        cap=PollutionCapture(URL+'?__proto__.x=1')
        self.assertEqual(scan(cap).to_json(),scan(cap).to_json())
    def test_json_valid(self):
        self.assertIn('findings',json.loads(scan(PollutionCapture(URL)).to_json()))
    def test_invalid_config(self):
        with self.assertRaises(ValueError): PollutionConfig(max_depth=0)
    def test_invalid_capture_skipped(self):
        self.assertEqual(scan('not capture').captures_skipped,1)
    def test_malformed_json_not_crash(self):
        self.assertFalse(scan(PollutionCapture(URL, request_body='{', content_type='application/json')).findings)
    def test_excessive_query_fields_not_crash(self):
        cap=PollutionCapture(URL+'?a=1&b=2&__proto__.x=1')
        self.assertFalse(scan(cap,config=PollutionConfig(max_query_pairs=1)).findings)

if __name__ == '__main__': unittest.main()

