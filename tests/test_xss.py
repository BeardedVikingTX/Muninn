import json
import unittest
from audit.xss import XSSAuditor, XSSCapture, XSSConfig, XSSInputError

URL = 'https://example.test/search?q=secret'
SCOPE = lambda url: url.startswith('https://example.test/')

class XSSTests(unittest.TestCase):
    def setUp(self):
        self.a = XSSAuditor()

    def report(self, **kwargs):
        return self.a.analyze([XSSCapture(url=URL, **kwargs)], scope_check=SCOPE)

    def codes(self, **kwargs):
        return {f.code for f in self.report(**kwargs).findings}

    def test_empty(self):
        self.assertEqual(self.report().findings, ())

    def test_text_reflection(self):
        self.assertIn('REFLECTION_HTML_TEXT', self.codes(marker='MARK123', response_body='<p>MARK123</p>'))

    def test_attribute_reflection(self):
        self.assertIn('REFLECTION_HTML_ATTRIBUTE', self.codes(marker='MARK123', response_body='<p title="MARK123">Hi</p>'))

    def test_event_attribute(self):
        self.assertIn('REFLECTION_EVENT_HANDLER_ATTRIBUTE', self.codes(marker='MARK123', response_body='<img onerror="MARK123">'))

    def test_url_attribute(self):
        self.assertIn('REFLECTION_URL_ATTRIBUTE', self.codes(marker='MARK123', response_body='<a href="MARK123">a</a>'))

    def test_style_attribute(self):
        self.assertIn('REFLECTION_STYLE_ATTRIBUTE', self.codes(marker='MARK123', response_body='<p style="MARK123">a</p>'))

    def test_script_text(self):
        self.assertIn('REFLECTION_SCRIPT_TEXT', self.codes(marker='MARK123', response_body='<script>const x="MARK123"</script>'))

    def test_json_reflection(self):
        self.assertIn('REFLECTION_NON_EXECUTABLE_RESPONSE', self.codes(marker='MARK123', response_body='{"v":"MARK123"}', content_type='application/json'))

    def test_js_reflection(self):
        self.assertIn('REFLECTION_SCRIPT_TEXT', self.codes(marker='MARK123', response_body='const x="MARK123";', content_type='application/javascript'))

    def test_no_reflection(self):
        self.assertFalse(any(c.startswith('REFLECTION') for c in self.codes(marker='MARK123', response_body='safe')))

    def test_stored_independent(self):
        self.assertIn('STORED_CROSS_SESSION_REFLECTION', self.codes(marker='MARK123', response_body='<p>MARK123</p>', stored=True, independent_session=True))

    def test_stored_not_independent(self):
        self.assertNotIn('STORED_CROSS_SESSION_REFLECTION', self.codes(marker='MARK123', response_body='<p>MARK123</p>', stored=True))

    def test_dom_sink(self):
        self.assertIn('DOM_SINK_INNERHTML', self.codes(js_source='const x=location.hash; node.innerHTML=x;'))

    def test_outerhtml(self):
        self.assertIn('DOM_SINK_OUTERHTML', self.codes(js_source='node.outerHTML=x;'))

    def test_adjacent(self):
        self.assertIn('DOM_SINK_INSERTADJACENTHTML', self.codes(js_source='node.insertAdjacentHTML("beforeend", x)'))

    def test_document_write(self):
        self.assertIn('DOM_SINK_DOCUMENT_WRITE', self.codes(js_source='document.write(x)'))

    def test_eval(self):
        self.assertIn('DOM_SINK_EVAL', self.codes(js_source='eval(x)'))

    def test_function(self):
        self.assertIn('DOM_SINK_FUNCTION', self.codes(js_source='new Function(x)'))

    def test_csp_inline(self):
        self.assertIn('CSP_UNSAFE_INLINE', self.codes(response_headers={'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline'"}))

    def test_csp_eval(self):
        self.assertIn('CSP_UNSAFE_EVAL', self.codes(response_headers={'Content-Security-Policy': "script-src 'unsafe-eval'"}))

    def test_trusted_execution(self):
        self.assertIn('TRUSTED_BROWSER_EXECUTION', self.codes(browser_executed=True, browser_evidence_trusted=True, execution_provenance='test-run-123'))

    def test_untrusted_execution(self):
        self.assertNotIn('TRUSTED_BROWSER_EXECUTION', self.codes(browser_executed=True, execution_provenance='test-run-123'))

    def test_no_provenance(self):
        self.assertNotIn('TRUSTED_BROWSER_EXECUTION', self.codes(browser_executed=True, browser_evidence_trusted=True))

    def test_out_of_scope(self):
        with self.assertRaises(XSSInputError):
            self.a.analyze([XSSCapture(url='https://other.test/')], scope_check=SCOPE)

    def test_missing_scope(self):
        with self.assertRaises(XSSInputError):
            self.a.analyze([XSSCapture(url=URL)], scope_check=None)

    def test_invalid_url(self):
        with self.assertRaises(XSSInputError):
            self.a.analyze(
                [XSSCapture(url="javascript:alert(1)")],
                scope_check=SCOPE,
            )

