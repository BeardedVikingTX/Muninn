import base64
import tempfile
import unittest
from pathlib import Path
from passive_engine import analyze_burp, _allowed

SCOPE = {'in_scope': [{'kind':'host','value':'api.box.com'}], 'out_of_scope':[{'kind':'wildcard','value':'*.signrequest.com'}]}

class PassiveTests(unittest.TestCase):
    def test_exact_host(self):
        self.assertTrue(_allowed('https://api.box.com/files', SCOPE))
        for url in ('https://evilapi.box.com/', 'https://api.box.com.evil.org/', 'https://signrequest.com/', 'javascript:foo', 'https://user@api.box.com/'):
            self.assertFalse(_allowed(url, SCOPE), url)
    def test_passive_cors(self):
        req = b'GET / HTTP/1.1\r\nOrigin: https://example.net\r\n\r\n'
        resp = b'HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://example.net\r\nAccess-Control-Allow-Credentials: true\r\n\r\nhello'
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'burp.xml'
            p.write_text('<items><item><url>https://api.box.com/</url><request base64="true">'+base64.b64encode(req).decode()+'</request><response base64="true">'+base64.b64encode(resp).decode()+'</response></item></items>')
            result = analyze_burp(p, SCOPE, ['cors'])
            self.assertEqual(result['stats']['in_scope'], 1)
            self.assertEqual(result['findings'][0]['verification'], 'not_verified')
    def test_out_of_scope_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'burp.xml'
            p.write_text('<items><item><url>https://other.box.com/</url></item></items>')
            result=analyze_burp(p, SCOPE, ['cors'])
            self.assertEqual(result['stats']['out_of_scope'], 1)
            self.assertEqual(result['findings'], [])

if __name__ == '__main__': unittest.main()
