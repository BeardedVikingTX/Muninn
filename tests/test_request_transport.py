import unittest
import time
from concurrent.futures import ThreadPoolExecutor
from core.http_models import HTTPRequest, HTTPResponse, Headers, Header
from core.scope_engine import ScopeEngine
from core.request_transport import (RequestTransport, TransportApproval, TransportConfig,
    TransportDenied, TransportFailure)

URL = 'https://example.com/search?q=1'

def scope():
    return ScopeEngine.from_mapping({'program':'test','in_scope':[{'kind':'host','value':'example.com'}],
        'out_of_scope':[], 'excluded_assets':[]})

def approval(**kwargs):
    args = dict(engagement_id='test-01', approved_by='operator', expires_at=time.time()+100,
                allowed_methods=frozenset({'GET'}), max_requests=3, active_permission=True)
    args.update(kwargs)
    return TransportApproval(**args)

def request(**kwargs):
    args = dict(method='GET',target='/search?q=1',source_url=URL)
    args.update(kwargs)
    return HTTPRequest(**args)

class RequestTransportTests(unittest.TestCase):
    def setUp(self):
        self.calls=[]
        def adapter(url, req, *, timeout, max_response_bytes):
            self.calls.append(url)
            return HTTPResponse(status_code=200,body=b'ok')
        self.adapter=adapter
        self.transport=RequestTransport(scope=scope(),approval=approval(),adapter=adapter)

    def test_valid(self):
        result=self.transport.send(URL,request(),permission_confirmed=True)
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.safe_summary()['response_bytes'],2)
    def test_default_offline(self):
        t=RequestTransport(scope=scope(),approval=approval())
        with self.assertRaises(TransportDenied): t.send(URL,request(),permission_confirmed=True)
    def test_permission_required(self):
        with self.assertRaises(TransportDenied): self.transport.send(URL,request())
        self.assertEqual(self.transport.attempts,0)
    def test_approval_disabled(self):
        t=RequestTransport(scope=scope(),approval=approval(active_permission=False),adapter=self.adapter)
        with self.assertRaises(TransportDenied): t.send(URL,request(),permission_confirmed=True)
    def test_expired(self):
        t=RequestTransport(scope=scope(),approval=approval(expires_at=time.time()-1),adapter=self.adapter)
        with self.assertRaises(TransportDenied): t.send(URL,request(),permission_confirmed=True)
    def test_out_of_scope(self):
        with self.assertRaises(TransportDenied): self.transport.send('https://other.com/search?q=1',request(source_url=None),permission_confirmed=True)
    def test_mismatch(self):
        with self.assertRaises(TransportDenied): self.transport.send(URL,request(target='/other'),permission_confirmed=True)
    def test_sensitive_header(self):
        with self.assertRaises(TransportDenied): self.transport.send(URL,request(headers=Headers((Header('Authorization','Bearer secret'),))),permission_confirmed=True)
    def test_raw_replay(self):
        with self.assertRaises(TransportDenied): self.transport.send(URL,request(raw=b'GET / HTTP/1.1\r\n\r\n'),permission_confirmed=True)
    def test_method_not_approved(self):
        with self.assertRaises(TransportDenied): self.transport.send(URL,request(method='POST'),permission_confirmed=True)
    def test_budget(self):
        for _ in range(3): self.transport.send(URL,request(),permission_confirmed=True)
        with self.assertRaises(TransportDenied): self.transport.send(URL,request(),permission_confirmed=True)
    def test_failure_consumes_budget(self):
        def broken(*a,**k): raise RuntimeError('secret')
        t=RequestTransport(scope=scope(),approval=approval(max_requests=1),adapter=broken)
        with self.assertRaisesRegex(TransportFailure,'adapter failed'): t.send(URL,request(),permission_confirmed=True)
        self.assertEqual(t.attempts,1)
    def test_oversized_response(self):
        t=RequestTransport(scope=scope(),approval=approval(),config=TransportConfig(max_response_bytes=1),
            adapter=lambda *a,**k: HTTPResponse(status_code=200,body=b'xx'))
        with self.assertRaises(TransportFailure): t.send(URL,request(),permission_confirmed=True)
    def test_oversized_request(self):
        t=RequestTransport(scope=scope(),approval=approval(),config=TransportConfig(max_request_bytes=1),adapter=self.adapter)
        with self.assertRaises(TransportDenied): t.send(URL,request(body=b'xx'),permission_confirmed=True)
    def test_bad_response(self):
        t=RequestTransport(scope=scope(),approval=approval(),adapter=lambda *a,**k: None)
        with self.assertRaises(TransportFailure): t.send(URL,request(),permission_confirmed=True)
    def test_concurrent_budget(self):
        with ThreadPoolExecutor(max_workers=12) as pool:
            futures=[pool.submit(self.transport.send,URL,request(),permission_confirmed=True) for _ in range(20)]
        self.assertEqual(sum(f.exception() is None for f in futures),3)
        self.assertEqual(self.transport.attempts,3)
    def test_no_credentials_in_repr(self):
        self.assertNotIn('secret',repr(request(headers=Headers((Header('X-Example','secret'),)))))
    def test_redirect_not_followed_by_layer(self):
        t=RequestTransport(scope=scope(),approval=approval(),adapter=lambda *a,**k: HTTPResponse(status_code=302,headers=Headers((Header('Location','https://evil.com'),))))
        self.assertEqual(t.send(URL,request(),permission_confirmed=True).status_code,302)
    def test_invalid_approval(self):
        with self.assertRaises(ValueError): approval(max_requests=0)

if __name__=='__main__': unittest.main()

