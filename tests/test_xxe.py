import json
import unittest
from audit.xxe import XXEAuditor, XXEConfig, XXEObservation, XXEOASTEvent

URL = 'https://example.test/api/xml?token=SUPERSECRET'
SCOPE = lambda url: url.startswith('https://example.test/')


def run(xml='', **kwargs):
    return XXEAuditor().analyze([XXEObservation(url=URL, request_xml=xml, **kwargs)], scope_check=SCOPE)


def rules(report):
    return {f.rule for f in report.findings}


class XXETests(unittest.TestCase):
    def test_empty(self): self.assertEqual(len(run().findings), 0)
    def test_doctype(self): self.assertIn('doctype_present', rules(run('<!DOCTYPE x><x/>')))
    def test_external_dtd(self): self.assertIn('external_dtd', rules(run('<!DOCTYPE x SYSTEM "https://test.invalid/d"><x/>')))
    def test_public_dtd(self): self.assertIn('external_dtd', rules(run('<!DOCTYPE x PUBLIC "id" "https://test.invalid/d"><x/>')))
    def test_entity(self): self.assertIn('external_entity', rules(run('<!DOCTYPE x [<!ENTITY e SYSTEM "https://test.invalid/">]><x/>')))
    def test_parameter_entity(self): self.assertIn('parameter_entity', rules(run('<!DOCTYPE x [<!ENTITY % e SYSTEM "https://test.invalid/">]><x/>')))
    def test_xinclude(self): self.assertIn('xinclude', rules(run('<x xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="https://test.invalid"/></x>')))
    def test_xinclude_requires_namespace(self): self.assertNotIn('xinclude', rules(run('<xi:include href="https://test.invalid"/>')))
    def test_schema(self): self.assertIn('schema_location', rules(run('<x xsi:schemaLocation="a b"/>')))
    def test_expansion(self): self.assertIn('entity_expansion_pattern', rules(run('<!DOCTYPE x [<!ENTITY e "x">]><x>' + '&e;'*9 + '</x>')))
    def test_no_expansion(self): self.assertNotIn('entity_expansion_pattern', rules(run('<x>' + '&e;'*9 + '</x>')))
    def test_parser_error(self): self.assertIn('xml_parser_error', rules(run(response_text='SAXParseException: invalid XML')))
    def test_baseline_suppression(self): self.assertNotIn('xml_parser_error', rules(run(response_text='SAXParseException', baseline_response_text='SAXParseException')))
    def test_status_diff(self): self.assertIn('status_differential', rules(run('<!DOCTYPE x>', status=500, baseline_status=200)))
    def test_status_diff_no_doctype(self): self.assertNotIn('status_differential', rules(run('<x/>', status=500, baseline_status=200)))
    def test_marker_trusted(self): self.assertIn('verified_entity_marker', rules(run(marker_verified=True, marker_provenance='fixture-1')))
    def test_marker_requires_provenance(self): self.assertNotIn('verified_entity_marker', rules(run(marker_verified=True)))
    def test_boundary_trusted(self): self.assertIn('verified_boundary_violation', rules(run(boundary_violation_verified=True, boundary_provenance='fixture-1')))
    def test_boundary_requires_provenance(self): self.assertNotIn('verified_boundary_violation', rules(run(boundary_violation_verified=True)))
    def test_oast_http(self):
        report = XXEAuditor().analyze([XXEObservation(URL, correlation_id='c')], scope_check=SCOPE, oast_events=[XXEOASTEvent('c', 'http', True, True, 'fixture')])
        self.assertIn('oast_http_callback', rules(report))
    def test_oast_dns(self):
        report = XXEAuditor().analyze([XXEObservation(URL, correlation_id='c')], scope_check=SCOPE, oast_events=[XXEOASTEvent('c', 'dns', True, True, 'fixture')])
        self.assertIn('oast_dns_callback', rules(report))
    def test_oast_untrusted(self):
        report = XXEAuditor().analyze([XXEObservation(URL, correlation_id='c')], scope_check=SCOPE, oast_events=[XXEOASTEvent('c', 'http', False, True, 'fixture')])
        self.assertNotIn('oast_http_callback', rules(report))
    def test_oast_wrong_id(self):
        report = XXEAuditor().analyze([XXEObservation(URL, correlation_id='c')], scope_check=SCOPE, oast_events=[XXEOASTEvent('d', 'http', True, True, 'fixture')])
        self.assertNotIn('oast_http_callback', rules(report))
    def test_oast_requires_provenance(self):
        report = XXEAuditor().analyze([XXEObservation(URL, correlation_id='c')], scope_check=SCOPE, oast_events=[XXEOASTEvent('c', 'http', True, True)])
        self.assertNotIn('oast_http_callback', rules(report))
    def test_scope(self):
        report = XXEAuditor().analyze([XXEObservation('https://other.test/', '<!DOCTYPE x>')], scope_check=SCOPE)
        self.assertEqual(report.observations_skipped, 1)
    def test_invalid_url(self):
        report = XXEAuditor().analyze([XXEObservation('file:///etc/passwd', '<!DOCTYPE x>')], scope_check=lambda _: True)
        self.assertEqual(report.observations_skipped, 1)
    def test_bad_port(self):
        report = XXEAuditor().analyze([XXEObservation('https://example.test:bad/', '<!DOCTYPE x>')], scope_check=lambda _: True)
        self.assertEqual(report.observations_skipped, 1)
    def test_userinfo(self):
        report = XXEAuditor().analyze([XXEObservation('https://name:pass@example.test/', '<!DOCTYPE x>')], scope_check=lambda _: True)
        self.assertEqual(report.observations_skipped, 1)
    def test_no_scope(self):
        with self.assertRaises(TypeError): XXEAuditor().analyze([] , scope_check=None)
    def test_limit_observations(self):
        a = XXEAuditor(XXEConfig(max_observations=1))
        self.assertEqual(a.analyze([XXEObservation(URL), XXEObservation(URL)], scope_check=SCOPE).observations_processed, 1)
    def test_limit_size(self):
        a = XXEAuditor(XXEConfig(max_xml_bytes=5))
        self.assertEqual(a.analyze([XXEObservation(URL, '<!DOCTYPE x>')], scope_check=SCOPE).observations_skipped, 1)
    def test_limit_response_size(self):
        a = XXEAuditor(XXEConfig(max_response_bytes=5))
        self.assertEqual(a.analyze([XXEObservation(URL, response_text='SAXParseException')], scope_check=SCOPE).observations_skipped, 1)
    def test_max_findings(self):
        a = XXEAuditor(XXEConfig(max_findings=1))
        r = a.analyze([XXEObservation(URL, '<!DOCTYPE x SYSTEM "a">')], scope_check=SCOPE)
        self.assertEqual(len(r.findings), 1)
    def test_dedupe(self):
        r = XXEAuditor().analyze([XXEObservation(URL, '<!DOCTYPE x>'), XXEObservation(URL, '<!DOCTYPE x>')], scope_check=SCOPE)
        self.assertEqual(len(r.findings), 1)
    def test_different_scenarios(self):
        r = XXEAuditor().analyze([XXEObservation(URL, '<!DOCTYPE x>', scenario='a'), XXEObservation(URL, '<!DOCTYPE x>', scenario='b')], scope_check=SCOPE)
        self.assertEqual(len(r.findings), 2)
    def test_redacts_query(self):
        self.assertNotIn('SUPERSECRET', run('<!DOCTYPE x>').to_json())
    def test_redacts_xml(self):
        self.assertNotIn('SECRET_PAYLOAD', run('<!DOCTYPE x [<!ENTITY e "SECRET_PAYLOAD">]>').to_json())
    def test_redacts_path(self):
        r = XXEAuditor().analyze([XXEObservation('https://example.test/SECRET_PATH', '<!DOCTYPE x>')], scope_check=SCOPE)
        self.assertNotIn('SECRET_PATH', r.to_json())
    def test_redacts_provenance(self):
        self.assertNotIn('SECRET_PROVENANCE', run(marker_verified=True, marker_provenance='SECRET_PROVENANCE').to_json())
    def test_deterministic(self): self.assertEqual(run('<!DOCTYPE x>').to_json(), run('<!DOCTYPE x>').to_json())
    def test_valid_json(self): self.assertIsInstance(json.loads(run('<!DOCTYPE x>').to_json())['findings'], list)
    def test_config_invalid(self):
        with self.assertRaises(ValueError): XXEAuditor(XXEConfig(max_findings=0))
    def test_no_network(self):
        self.assertNotIn('oast_http_callback', rules(run('<!DOCTYPE x SYSTEM "http://example.invalid/">')))

if __name__ == '__main__': unittest.main()

