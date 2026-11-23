import json
import unittest
from audit.graphql import GraphQLAuditor, GraphQLCapture, _depth

URL = 'https://example.test/graphql'

def cap(**kw):
    base = dict(method='POST', url=URL, status=200,
                request_headers={'Content-Type':'application/json'},
                request_body=json.dumps({'query':'query { viewer { id } }'}),
                response_headers={}, response_body='{"data":{"viewer":{"id":"1"}}}')
    base.update(kw)
    return GraphQLCapture(**base)

class TestGraphQL(unittest.TestCase):
    def setUp(self):
        self.a = GraphQLAuditor(depth_threshold=3)
        self.scope = lambda u: u == URL
    def test_baseline(self): self.assertEqual(self.a.analyze([cap()], scope_check=self.scope).findings, [])
    def test_scope(self): self.assertEqual(self.a.analyze([cap()], scope_check=lambda _:False).skipped, 1)
    def test_scope_exception(self): self.assertEqual(self.a.analyze([cap()], scope_check=lambda _:1/0).skipped, 1)
    def test_missing_scope(self):
        with self.assertRaises(TypeError): self.a.analyze([cap()], scope_check=None)
    def test_invalid_url(self): self.assertEqual(self.a.analyze([cap(url='file:///tmp/a')],scope_check=lambda _:True).skipped,1)
    def test_unrelated(self): self.assertEqual(self.a.analyze([cap(url='https://example.test/api', request_body='{}')],scope_check=lambda _:True).skipped,1)
    def test_mutation_get(self):
        c=cap(method='GET',request_body='{"query":"mutation { updateName(name: \\"x\\") { ok } }"}')
        self.assertIn('MUTATION_OVER_GET',[f.code for f in self.a.analyze([c],scope_check=self.scope).findings])
    def test_depth(self): self.assertEqual(_depth('query { a { b { c } } }'), 3)
    def test_depth_strings(self): self.assertEqual(_depth('query { a(arg:"{ }") { b } }'), 2)
    def test_deep(self):
        c=cap(request_body=json.dumps({'query':'{ a { b { c { d } } } }'}))
        self.assertIn('DEEP_QUERY_OBSERVED',[f.code for f in self.a.analyze([c],scope_check=self.scope).findings])
    def test_batch(self):
        c=cap(request_body=json.dumps([{'query':'{a}'},{'query':'{b}'}]))
        self.assertIn('BATCHED_OPERATIONS_OBSERVED',[f.code for f in self.a.analyze([c],scope_check=self.scope).findings])
    def test_introspection(self):
        c=cap(request_body=json.dumps({'query':'{ __schema { types { name } } }'}),response_body='{"data":{"__schema":{"types":[]}}}')
        self.assertIn('INTROSPECTION_RESPONSE',[f.code for f in self.a.analyze([c],scope_check=self.scope).findings])
    def test_introspection_no_data(self):
        c=cap(request_body=json.dumps({'query':'{ __schema { types { name } } }'}),response_body='{"errors":[]}')
        self.assertNotIn('INTROSPECTION_RESPONSE',[f.code for f in self.a.analyze([c],scope_check=self.scope).findings])
    def test_shared_cache(self):
        c=cap(authenticated=True,response_headers={'Cache-Control':'public, max-age=60'})
        self.assertIn('POTENTIALLY_SHARED_CACHE',[f.code for f in self.a.analyze([c],scope_check=self.scope).findings])
    def test_private_cache(self):
        c=cap(authenticated=True,response_headers={'Cache-Control':'private, max-age=60'})
        self.assertNotIn('POTENTIALLY_SHARED_CACHE',[f.code for f in self.a.analyze([c],scope_check=self.scope).findings])
    def test_error_stack(self):
        c=cap(response_body='{"errors":[{"extensions":{"stacktrace":["secret"]}}]}')
        r=self.a.analyze([c],scope_check=self.scope)
        self.assertIn('ERROR_INTERNALS_EXPOSED',[f.code for f in r.findings]);self.assertNotIn('secret',r.to_json())
    def test_private_get(self):
        c=cap(method='GET',expected_private=True)
        self.assertIn('PRIVATE_DATA_OVER_GET',[f.code for f in self.a.analyze([c],scope_check=self.scope).findings])
    def test_dedupe(self):
        r=self.a.analyze([cap(authenticated=True,response_headers={'Cache-Control':'public'})]*3,scope_check=self.scope)
        self.assertEqual(len(r.findings),1)
    def test_limits(self):
        a=GraphQLAuditor(max_captures=1)
        self.assertEqual(a.analyze([cap(),cap()],scope_check=self.scope).analyzed,1)
    def test_invalid_limits(self):
        with self.assertRaises(ValueError): GraphQLAuditor(max_findings=0)
    def test_json_deterministic(self):
        self.assertEqual(self.a.analyze([cap()],scope_check=self.scope).to_json(),self.a.analyze([cap()],scope_check=self.scope).to_json())
    def test_no_secrets_in_output(self):
        c=cap(request_headers={'Authorization':'Bearer supersecret'},response_body='{"data":{"token":"verysecret"}}')
        r=self.a.analyze([c],scope_check=self.scope).to_json()
        self.assertNotIn('supersecret',r);self.assertNotIn('verysecret',r)
    def test_raw_graphql(self):
        c=cap(request_headers={'Content-Type':'application/graphql'},request_body='{ viewer { id } }')
        self.assertEqual(self.a.analyze([c],scope_check=self.scope).analyzed,1)

if __name__=='__main__': unittest.main()

