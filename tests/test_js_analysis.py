import json
import unittest
from audit.js_analysis import JSAnalyzer, JSAsset, JSConfig

URL = "https://example.test/static/app.js"


def scan(source, **kwargs):
    return JSAnalyzer(kwargs.get("config")).analyze([JSAsset(URL, source)], scope_check=kwargs.get("scope_check", lambda u: True))


class JSAnalysisTests(unittest.TestCase):
    def test_empty(self): self.assertEqual(len(scan("const a = 1;").findings), 0)
    def test_aws_key(self): self.assertIn("AWS_ACCESS_KEY", [x.rule_id for x in scan("const x='AKIAABCDEFGHIJKLMNOP';").findings])
    def test_private_key(self): self.assertIn("PRIVATE_KEY", [x.rule_id for x in scan("-----BEGIN PRIVATE KEY-----").findings])
    def test_github_token(self): self.assertIn("GITHUB_TOKEN", [x.rule_id for x in scan("ghp_" + "a"*30).findings])
    def test_slack_token(self): self.assertIn("SLACK_TOKEN", [x.rule_id for x in scan("xoxb-" + "1"*15).findings])
    def test_stripe_key(self): self.assertIn("STRIPE_SECRET", [x.rule_id for x in scan("sk_live_" + "A"*20).findings])
    def test_secret_assignment(self): self.assertIn("SECRET_ASSIGNMENT", [x.rule_id for x in scan('password="StrongPassphrase123"').findings])
    def test_placeholder(self): self.assertNotIn("SECRET_ASSIGNMENT", [x.rule_id for x in scan('password="changeme"').findings])
    def test_eval(self): self.assertIn("DYNAMIC_EVAL", [x.rule_id for x in scan("eval(userInput)").findings])
    def test_function(self): self.assertIn("DYNAMIC_EVAL", [x.rule_id for x in scan("Function(text)").findings])
    def test_inner_html(self): self.assertIn("DOM_HTML_SINK", [x.rule_id for x in scan("node.innerHTML = data").findings])
    def test_insert_html(self): self.assertIn("DOM_HTML_SINK", [x.rule_id for x in scan("node.insertAdjacentHTML('beforeend',data)").findings])
    def test_document_write(self): self.assertIn("DOCUMENT_WRITE", [x.rule_id for x in scan("document.write(x)").findings])
    def test_postmessage(self): self.assertIn("POSTMESSAGE_WILDCARD", [x.rule_id for x in scan("window.postMessage(msg, '*')").findings])
    def test_message_listener(self): self.assertIn("MESSAGE_LISTENER", [x.rule_id for x in scan("window.addEventListener('message', callback)").findings])
    def test_storage(self): self.assertIn("STORAGE_TOKEN", [x.rule_id for x in scan("localStorage.setItem('token', data)").findings])
    def test_sourcemap(self): self.assertIn("SOURCE_MAP_REFERENCE", [x.rule_id for x in scan("//# sourceMappingURL=app.js.map").findings])
    def test_debugger(self): self.assertIn("DEBUGGER_STATEMENT", [x.rule_id for x in scan("debugger;").findings])
    def test_api_path(self): self.assertIn("ENDPOINT_REFERENCE", [x.rule_id for x in scan("fetch('/api/v1/users')").findings])
    def test_graphql_path(self): self.assertIn("ENDPOINT_REFERENCE", [x.rule_id for x in scan("const path='/graphql/query'").findings])
    def test_external_url_not_collected(self): self.assertNotIn("ENDPOINT_REFERENCE", [x.rule_id for x in scan("'https://outside.test/api/users'").findings])
    def test_scope_required(self):
        with self.assertRaises(ValueError): JSAnalyzer().analyze([], scope_check=None)
    def test_scope_deny(self): self.assertEqual(scan("eval(x)", scope_check=lambda u: False).skipped, 1)
    def test_scope_exception(self):
        def fail(u): raise RuntimeError("no")
        self.assertEqual(scan("eval(x)", scope_check=fail).skipped, 1)
    def test_invalid_url(self):
        self.assertEqual(JSAnalyzer().analyze([JSAsset("file:///tmp/x.js", "eval(x)")], scope_check=lambda u: True).skipped, 1)
    def test_max_bytes(self): self.assertEqual(scan("eval(x)", config=JSConfig(max_asset_bytes=3)).skipped, 1)
    def test_max_assets(self):
        report = JSAnalyzer(JSConfig(max_assets=1)).analyze([JSAsset(URL,"eval(x)"),JSAsset(URL,"eval(y)")], scope_check=lambda u: True)
        self.assertEqual(report.assets_seen, 1)
    def test_max_findings(self): self.assertEqual(len(scan("eval(a);eval(b);eval(c)", config=JSConfig(max_findings=2)).findings), 2)
    def test_per_rule_limit(self): self.assertEqual(len(scan("eval(a);eval(b);eval(c)", config=JSConfig(max_matches_per_rule_per_asset=1)).findings), 1)
    def test_no_secrets_in_json(self):
        secret = "SuperSecretValue123"
        self.assertNotIn(secret, scan('password="'+secret+'"').to_json())
    def test_no_source_in_json(self): self.assertNotIn("eval(userInput)", scan("eval(userInput)").to_json())
    def test_json_parseable(self): self.assertIn("findings", json.loads(scan("eval(x)").to_json()))
    def test_deterministic(self): self.assertEqual(scan("eval(x)").to_json(), scan("eval(x)").to_json())
    def test_line_number(self): self.assertEqual(scan("const x=1;\neval(x)").findings[0].line, 2)
    def test_empty_assets(self): self.assertEqual(JSAnalyzer().analyze([], scope_check=lambda u: True).assets_seen, 0)
    def test_low_confidence_filter(self): self.assertNotIn("DOM_HTML_SINK", [f.rule_id for f in scan("x.innerHTML = y", config=JSConfig(include_low_confidence=False)).findings])
    def test_invalid_limits(self):
        with self.assertRaises(ValueError): JSConfig(max_assets=0)
    def test_counts(self):
        report = JSAnalyzer().analyze([JSAsset(URL,"eval(x)"), JSAsset("http://invalid.test/a.js", "eval(x)")], scope_check=lambda u: u.startswith("https://"))
        self.assertEqual((report.assets_seen, report.assets_analyzed, report.skipped), (2,1,1))

if __name__ == "__main__": unittest.main()

