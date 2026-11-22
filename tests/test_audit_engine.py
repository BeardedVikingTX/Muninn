import tempfile
import unittest
from pathlib import Path

from core.audit_engine import AuditEngine, AuditEngineError
from core.audit_logger import AuditLogger
from core.http_models import HTTPRequest, HTTPTransaction, Header, Headers
from core.payload_loader import validate_payload
from core.scope_engine import ScopeEngine


def scope():
    return ScopeEngine.from_mapping({'program':'test', 'in_scope':[{'kind':'host','value':'example.test'}], 'out_of_scope':[{'kind':'host','value':'blocked.test'}]})


def payload(**changes):
    data = {'schema_version':1, 'id':'PROBE-001', 'name':'marker', 'category':'xss',
            'payload':{'template':'marker_{{nonce}}', 'encoding':'none'},
            'contexts':['query','json'],
            'execution':{'mode':'authorized_active','requires_scope':True,'requires_active_permission':True,'max_requests':1},
            'detection':{'type':'response_contains_marker','confidence':'informational'},
            'safety':{'destructive':False,'out_of_band':False,'requires_manual_review':False}}
    for k,v in changes.items():
        if isinstance(v,dict) and isinstance(data.get(k),dict): data[k].update(v)
        else: data[k]=v
    return validate_payload(data)


def tx(source='source-1', url='https://example.test/search?q=one', target='/search?q=one', body=b'', content_type=None):
    hs = [Header('Host','example.test')]
    if content_type: hs.append(Header('Content-Type', content_type))
    return HTTPTransaction(source, HTTPRequest('POST' if body else 'GET',target,headers=Headers(tuple(hs)),body=body,source_url=url))


class EngineTests(unittest.TestCase):
    def engine(self, **kw): return AuditEngine(scope=scope(), definitions=(payload(),), **kw)

    def test_candidate_no_execution_budget(self):
        result = self.engine().plan([tx()], run_id='run-1')
        self.assertEqual(result.summary.candidates,1)
        self.assertEqual(result.tests[0].request_budget,0)
        self.assertEqual(result.tests[0].reason_code,'INDEPENDENT_AUTH_REQUIRED')

    def test_determinism(self):
        a = self.engine().plan([tx()], run_id='run-1')
        b = self.engine().plan([tx()], run_id='run-1')
        self.assertEqual(a,b)

    def test_scope_rejects_other_hosts(self):
        result = self.engine().plan([tx(url='https://other.test/search?q=one')], run_id='run-1')
        self.assertEqual(result.summary.scope_denied,1)
        self.assertEqual(len(result.tests),0)

    def test_target_mismatch_denied(self):
        result = self.engine().plan([tx(target='/different?q=one')],run_id='run-1')
        self.assertEqual(result.summary.scope_denied,1)

    def test_sensitive_query_blocked(self):
        result = self.engine().plan([tx(url='https://example.test/search?token=secret',target='/search?token=secret')],run_id='run-1')
        self.assertEqual(result.summary.blocked,1)
        self.assertEqual(result.tests[0].request_budget,0)

    def test_manual_review(self):
        p = payload(safety={'requires_manual_review':True})
        result = AuditEngine(scope=scope(),definitions=(p,)).plan([tx()],run_id='run-1')
        self.assertEqual(result.summary.manual_review,1)

    def test_passive_mode(self):
        p = payload(execution={'mode':'passive','max_requests':0}, detection={'type':'manual_review'})
        result = AuditEngine(scope=scope(),definitions=(p,)).plan([tx()],run_id='run-1')
        self.assertEqual(result.tests[0].reason_code,'PASSIVE_ONLY')

    def test_invalid_catalog(self):
        p = payload(payload={'template':'{{unknown}}'})
        with self.assertRaises(AuditEngineError): AuditEngine(scope=scope(),definitions=(p,))

    def test_transaction_limit(self):
        with self.assertRaises(AuditEngineError):
            self.engine(max_transactions=1).plan([tx(),tx('source-2')],run_id='run-1')

    def test_test_limit(self):
        with self.assertRaises(AuditEngineError):
            self.engine(max_tests=1).plan([tx(),tx('source-2')],run_id='run-1')

    def test_invalid_run_id(self):
        with self.assertRaises(ValueError): self.engine().plan([],run_id='bad id')

    def test_duplicate_source_deduplication(self):
        result = self.engine().plan([tx(),tx()],run_id='run-1')
        self.assertEqual(len(result.tests),1)

    def test_json_fields(self):
        result = self.engine().plan([tx(url='https://example.test/search',target='/search',body=b'{"x":1,"token":"hidden"}',content_type='application/json')],run_id='run-1')
        self.assertEqual(result.summary.blocked,1)
        self.assertEqual(result.summary.candidates,1)

    def test_private_summary(self):
        result = self.engine().plan([tx(url='https://example.test/search?token=SECRET',target='/search?token=SECRET')],run_id='run-1')
        self.assertNotIn('SECRET',repr(result.safe_summary()))
        self.assertNotIn('SECRET',repr(result.tests))

    def test_logger_integration(self):
        with tempfile.TemporaryDirectory() as directory:
            logger=AuditLogger(Path(directory)/'events.jsonl')
            result=self.engine(logger=logger).plan([tx()],run_id='run-1')
            self.assertEqual(result.summary.candidates,1)
            self.assertTrue(logger.verify().valid)
            self.assertGreater(logger.verify().count,2)

    def test_logger_fail_closed(self):
        class Broken:
            def record(self,*args,**kwargs): raise OSError('secret content')
        with self.assertRaisesRegex(AuditEngineError,'journal write failed'):
            self.engine(logger=Broken()).plan([tx()],run_id='run-1')

    def test_empty(self):
        result=self.engine().plan([],run_id='run-1')
        self.assertEqual(result.summary.transactions,0)

    def test_invalid_limits(self):
        for kw in ({'max_tests':0},{'max_transactions':True},{'max_tests_per_point':300}):
            with self.assertRaises(ValueError): self.engine(**kw)


if __name__=='__main__': unittest.main()

