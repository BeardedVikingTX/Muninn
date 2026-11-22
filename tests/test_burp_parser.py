import base64
import tempfile
import unittest
from pathlib import Path

from core.burp_parser import BurpParser, BurpParseError, parse_burp_history


REQ = b'GET /hello?q=1 HTTP/1.1\r\nHost: example.org\r\n\r\n'
RESP = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello'


def xml_item(req=REQ, resp=RESP, *, method='GET', url='https://example.org/hello?q=1', req_base64=True):
    req_text = base64.b64encode(req).decode() if req_base64 else req.decode('latin-1')
    resp_text = base64.b64encode(resp).decode() if resp is not None else ''
    return f'''<item><time>2026-11-22</time><url>{url.replace('&', '&amp;')}</url><host>example.org</host><port>443</port><protocol>https</protocol><method>{method}</method><request base64="{'true' if req_base64 else 'false'}">{req_text}</request><response base64="true">{resp_text}</response></item>'''


class BurpParserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'history.xml'

    def write(self, data):
        self.path.write_bytes(data.encode() if isinstance(data, str) else data)
        return self.path

    def test_roundtrip(self):
        self.write('<items>' + xml_item() + '</items>')
        tx = parse_burp_history(self.path)[0]
        self.assertEqual(tx.request.raw, REQ)
        self.assertEqual(tx.response.body, b'hello')
        self.assertEqual(tx.source_id, 'burp-00000001')

    def test_http2_textual_capture(self):
        req = b'GET /hello?q=1 HTTP/2\r\nHost: example.org\r\n\r\n'
        resp = b'HTTP/2 200\r\nContent-Type: text/plain\r\n\r\nhello'
        self.write('<items>' + xml_item(req=req, resp=resp) + '</items>')
        tx = parse_burp_history(self.path)[0]
        self.assertEqual(tx.request.version, 'HTTP/2')
        self.assertEqual(tx.response.version, 'HTTP/2')
        self.assertEqual(tx.response.body, b'hello')

    def test_stream_order(self):
        self.write('<items>' + xml_item() * 3 + '</items>')
        parser = BurpParser()
        self.assertEqual([t.source_id for t in parser.parse(self.path)], ['burp-00000001','burp-00000002','burp-00000003'])
        self.assertEqual(parser.processed, 3)

    def test_skip_invalid(self):
        self.write('<items>' + xml_item(method='POST') + xml_item() + '</items>')
        parser = BurpParser(skip_invalid=True)
        self.assertEqual(len(list(parser.parse(self.path))), 1)
        self.assertEqual(parser.issues[0].index, 1)

    def test_fail_closed(self):
        self.write('<items>' + xml_item(method='POST') + '</items>')
        with self.assertRaises(BurpParseError):
            parse_burp_history(self.path)

    def test_dtd_burp_compatible(self):
        self.write('<!DOCTYPE items [<!ELEMENT items (item*)><!ELEMENT item ANY>]><items>' + xml_item() + '</items>')
        self.assertEqual(len(parse_burp_history(self.path)), 1)

    def test_entity_blocked(self):
        self.write('<!DOCTYPE items [<!ENTITY secret "danger">]><items><item>&secret;</item></items>')
        with self.assertRaises(BurpParseError):
            parse_burp_history(self.path)

    def test_external_entity_blocked(self):
        self.write('<!DOCTYPE items [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><items><item>&xxe;</item></items>')
        with self.assertRaises(BurpParseError):
            parse_burp_history(self.path)

    def test_bad_base64(self):
        self.write('<items>' + xml_item().replace(base64.b64encode(REQ).decode(), '%%%') + '</items>')
        with self.assertRaises(BurpParseError):
            parse_burp_history(self.path)

    def test_no_response(self):
        self.write('<items>' + xml_item(resp=None) + '</items>')
        self.assertIsNone(parse_burp_history(self.path)[0].response)

    def test_bad_root(self):
        self.write('<root/>')
        with self.assertRaises(BurpParseError):
            parse_burp_history(self.path)

    def test_bad_xml(self):
        self.write('<items><item>')
        with self.assertRaises(BurpParseError):
            parse_burp_history(self.path)

    def test_file_size(self):
        self.write('<items/>')
        with self.assertRaises(BurpParseError):
            list(BurpParser(max_file_bytes=3).parse(self.path))

    def test_symlink(self):
        self.write('<items/>')
        link = Path(self.temp.name) / 'link.xml'
        link.symlink_to(self.path)
        with self.assertRaises(BurpParseError):
            parse_burp_history(link)

    def test_mismatch_host(self):
        self.write('<items>' + xml_item(url='https://other.example/hello') + '</items>')
        with self.assertRaises(BurpParseError):
            parse_burp_history(self.path)

    def test_no_network(self):
        self.write('<items>' + xml_item() + '</items>')
        import socket
        from unittest.mock import patch
        with patch.object(socket, 'create_connection', side_effect=AssertionError('network')):
            self.assertEqual(len(parse_burp_history(self.path)), 1)


if __name__ == '__main__':
    unittest.main()

