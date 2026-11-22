import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from core.http_models import HTTPRequest, HTTPResponse
from core.scope_engine import ScopeEngine
from core.execution_policy import ExecutionPolicy, ExecutionApproval, ExecutionLimits, PolicyDenied
from core.request_transport import RequestTransport, TransportApproval

URL = 'https://example.com/search?q=1'

def scope():
    return ScopeEngine.from_mapping({'program':'test','in_scope':[{'kind':'host','value':'example.com'}],
                                     'out_of_scope':[], 'excluded_assets':[]})

def approval(**kw):
    a = dict(engagement_id='run-01', approved_by='operator', expires_at=time.time()+120,
             allowed_methods=frozenset({'GET'}), active_permission=True,
             approved_categories=frozenset({'xss'}), max_requests=10)
    a.update(kw)
    return ExecutionApproval(**a)

def req(**kw):
    a = dict(method='GET', target='/search?q=1', source_url=URL)
    a.update(kw)
    return HTTPRequest(**a)

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.s = scope()
        self.p = ExecutionPolicy(scope=self.s, approval=approval())

    def reserve(self, policy=None, **kw):
        return (policy or self.p).reserve(URL, req(), category='xss', payload_id='probe-1', permission_confirmed=True, **kw)

    def deny(self, code, policy=None, **kw):
        with self.assertRaisesRegex(PolicyDenied, code):
            self.reserve(policy, **kw)

    def test_valid(self):
        x=self.reserve(); self.assertEqual(x.sequence,1); self.assertEqual(self.p.used,1)
        self.assertNotIn(URL, repr(x))
    def test_permission(self):
        with self.assertRaisesRegex(PolicyDenied, 'ACTIVE_PERMISSION_REQUIRED'):
            self.p.reserve(URL, req(), category='xss', payload_id='probe-1')
    def test_expired(self): self.deny('APPROVAL_EXPIRED', ExecutionPolicy(scope=self.s, approval=approval(expires_at=time.time()-1)))
    def test_disabled(self): self.deny('ACTIVE_PERMISSION_REQUIRED', ExecutionPolicy(scope=self.s, approval=approval(active_permission=False)))
    def test_category(self):
        with self.assertRaisesRegex(PolicyDenied,'CATEGORY_NOT_APPROVED'):
            self.p.reserve(URL,req(),category='sqli',payload_id='probe-1',permission_confirmed=True)
    def test_payload_allowlist(self): self.deny('PAYLOAD_NOT_APPROVED', ExecutionPolicy(scope=self.s,approval=approval(allowed_payload_ids=frozenset({'other'}))))
    def test_manual(self): self.deny('MANUAL_APPROVAL_REQUIRED', destructive=True)
    def test_oast(self): self.deny('MANUAL_APPROVAL_REQUIRED', out_of_band=True)
    def test_manual_review(self): self.deny('MANUAL_APPROVAL_REQUIRED', manual_review=True)
    def test_manual_granted(self): self.reserve(ExecutionPolicy(scope=self.s,approval=approval(manual_approval=True)),destructive=True)
    def test_out_of_scope(self):
        with self.assertRaisesRegex(PolicyDenied,'TARGET_NOT_IN_SCOPE'):
            self.p.reserve('https://other.com/search?q=1',req(source_url=None),category='xss',payload_id='probe-1',permission_confirmed=True)
    def test_exclusion(self):
        s=ScopeEngine.from_mapping({'program':'test','in_scope':[{'kind':'host','value':'example.com'}],
                                    'out_of_scope':[{'kind':'url','value':URL}], 'excluded_assets':[]})
        with self.assertRaisesRegex(PolicyDenied,'TARGET_NOT_IN_SCOPE'):
            ExecutionPolicy(scope=s,approval=approval()).reserve(URL,req(),category='xss',payload_id='probe-1',permission_confirmed=True)
    def test_scope_digest(self): self.deny('SCOPE_POLICY_CHANGED', ExecutionPolicy(scope=self.s,approval=approval(scope_digest='a'*64)))
    def test_method(self):
        with self.assertRaisesRegex(PolicyDenied,'METHOD_NOT_APPROVED'):
            self.p.reserve(URL,req(method='POST'),category='xss',payload_id='probe-1',permission_confirmed=True)
    def test_budget(self):
        p=ExecutionPolicy(scope=self.s,approval=approval(max_requests=1)); self.reserve(p); self.deny('GLOBAL_BUDGET_EXHAUSTED',p)
    def test_target_budget(self):
        p=ExecutionPolicy(scope=self.s,approval=approval(),limits=ExecutionLimits(max_requests_per_target=1)); self.reserve(p); self.deny('TARGET_BUDGET_EXHAUSTED',p)
    def test_category_budget(self):
        p=ExecutionPolicy(scope=self.s,approval=approval(),limits=ExecutionLimits(max_requests_per_category=1)); self.reserve(p); self.deny('CATEGORY_BUDGET_EXHAUSTED',p)
    def test_rate_limit(self):
        p=ExecutionPolicy(scope=self.s,approval=approval(),limits=ExecutionLimits(min_interval_seconds=10),clock=lambda: 100.0)
        # fixed clock requires future expiry
        self.reserve(p); self.deny('RATE_LIMITED',p)
    def test_stop(self): self.p.stop(); self.deny('EMERGENCY_STOP')
    def test_failure_stop(self):
        p=ExecutionPolicy(scope=self.s,approval=approval(),limits=ExecutionLimits(stop_after_failures=2)); p.report_failure(); p.report_failure(); self.deny('EMERGENCY_STOP',p)
    def test_raw(self):
        with self.assertRaisesRegex(PolicyDenied,'INVALID_REQUEST'):
            self.p.reserve(URL,req(raw=b'secret'),category='xss',payload_id='probe-1',permission_confirmed=True)
    def test_mismatch(self):
        with self.assertRaisesRegex(PolicyDenied,'TARGET_NOT_IN_SCOPE'):
            self.p.reserve(URL,req(target='/other'),category='xss',payload_id='probe-1',permission_confirmed=True)
    def test_size(self):
        p=ExecutionPolicy(scope=self.s,approval=approval(),limits=ExecutionLimits(max_request_bytes=1))
        with self.assertRaisesRegex(PolicyDenied,'REQUEST_TOO_LARGE'):
            p.reserve(URL,req(body=b'xx'),category='xss',payload_id='probe-1',permission_confirmed=True)
    def test_logger_failure(self):
        class Broken:
            def record(self,*a,**k): raise RuntimeError('secret')
        p=ExecutionPolicy(scope=self.s,approval=approval(),logger=Broken()); self.deny('AUDIT_LOG_UNAVAILABLE',p); self.assertEqual(p.used,0)
    def test_concurrency(self):
        p=ExecutionPolicy(scope=self.s,approval=approval(max_requests=5))
        def call(_):
            try: self.reserve(p); return True
            except PolicyDenied: return False
        with ThreadPoolExecutor(max_workers=12) as ex: outcomes=list(ex.map(call,range(50)))
        self.assertEqual(sum(outcomes),5); self.assertEqual(p.used,5)
    def test_transport_integration(self):
        calls=[]
        t=RequestTransport(scope=self.s,approval=TransportApproval('run-01','operator',time.time()+100,frozenset({'GET'}),10,True),
                           adapter=lambda *a,**kw: (calls.append(1) or HTTPResponse(status_code=200)))
        result=self.p.execute(t,URL,req(),category='xss',payload_id='probe-1',permission_confirmed=True)
        self.assertEqual(result.status_code,200); self.assertEqual(len(calls),1)
    def test_transport_failure_counts(self):
        t=RequestTransport(scope=self.s,approval=TransportApproval('run-01','operator',time.time()+100,frozenset({'GET'}),10,True),
                           adapter=lambda *a,**kw: (_ for _ in ()).throw(RuntimeError('secret')))
        p=ExecutionPolicy(scope=self.s,approval=approval(),limits=ExecutionLimits(stop_after_failures=1))
        with self.assertRaises(Exception): p.execute(t,URL,req(),category='xss',payload_id='probe-1',permission_confirmed=True)
        self.deny('EMERGENCY_STOP',p)
    def test_invalid_config(self):
        with self.assertRaises(ValueError): approval(max_requests=True)
        with self.assertRaises(ValueError): ExecutionLimits(min_interval_seconds=float('nan'))
    def test_no_network_by_default(self):
        self.reserve(); self.assertEqual(self.p.used,1)

if __name__ == '__main__': unittest.main()

