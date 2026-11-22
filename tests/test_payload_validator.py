import dataclasses
from pathlib import Path
import tempfile
import unittest

import yaml
from core.payload_loader import PayloadError, validate_payload
from core.payload_validator import PayloadValidator, lint_definition, validate_catalog


def example(**changes):
    data = {
        'schema_version': 1, 'id': 'INPUT-REFLECTION-001', 'name': 'Marker',
        'category': 'xss', 'description': '',
        'payload': {'template': 'muninn_{{nonce}}', 'encoding': 'none'},
        'contexts': ['query'],
        'execution': {'mode': 'authorized_active', 'requires_scope': True,
                      'requires_active_permission': True, 'max_requests': 1},
        'detection': {'type': 'response_contains_marker', 'confidence': 'informational'},
        'safety': {'destructive': False, 'out_of_band': False, 'requires_manual_review': False},
    }
    for k, v in changes.items():
        data[k] = v
    return validate_payload(data)


def codes(definition):
    return {item.code for item in lint_definition(definition)}


class PayloadValidatorTests(unittest.TestCase):
    def test_valid(self): self.assertFalse(codes(example()))
    def test_unknown_variable(self): self.assertIn('UNKNOWN_VARIABLE', codes(dataclasses.replace(example(), template='{{secret}}')))
    def test_bad_delimiter(self): self.assertIn('INVALID_TEMPLATE_SYNTAX', codes(dataclasses.replace(example(), template='{{nonce')))
    def test_jinja_expression(self): self.assertIn('INVALID_TEMPLATE_SYNTAX', codes(dataclasses.replace(example(), template='{% import os %}')))
    def test_oast_missing_variable(self):
        d = dataclasses.replace(example(), out_of_band=True, detection_type='oast_callback')
        self.assertIn('OAST_MARKER_MISSING', codes(d))
    def test_oast_valid(self):
        d = dataclasses.replace(example(), out_of_band=True, detection_type='oast_callback', template='{{oast_url}}')
        self.assertFalse(codes(d))
    def test_undeclared_oast(self): self.assertIn('UNDECLARED_OAST', codes(dataclasses.replace(example(), template='{{oast_url}}')))
    def test_callback_mismatch(self): self.assertIn('DETECTION_MISMATCH', codes(dataclasses.replace(example(), detection_type='oast_callback')))
    def test_passive_callback(self):
        d = dataclasses.replace(example(), mode='passive', max_requests=0, detection_type='oast_callback')
        self.assertIn('PASSIVE_DETECTION_MISMATCH', codes(d))
    def test_passive_destructive(self):
        d = dataclasses.replace(example(), mode='passive', max_requests=0, destructive=True, requires_manual_review=True)
        self.assertIn('PASSIVE_DESTRUCTIVE', codes(d))
    def test_destructive_budget(self):
        d = dataclasses.replace(example(), destructive=True, requires_manual_review=True, max_requests=2)
        self.assertIn('DESTRUCTIVE_REQUEST_BUDGET', codes(d))
    def test_missing_nonce_warning(self):
        d = dataclasses.replace(example(), template='static')
        report = validate_catalog([d])
        self.assertTrue(report.valid)
        self.assertEqual(report.safe_summary()['warnings'], 1)
    def test_header_encoding_mismatch(self):
        self.assertIn('ENCODING_CONTEXT_MISMATCH', codes(dataclasses.replace(example(), encoding='header')))
    def test_xml_encoding_mismatch(self):
        self.assertIn('ENCODING_CONTEXT_MISMATCH', codes(dataclasses.replace(example(), encoding='xml')))
    def test_duplicate_id(self):
        report = validate_catalog([example(), example()])
        self.assertFalse(report.valid)
        self.assertIn('DUPLICATE_ID', [x.code for x in report.diagnostics])
    def test_limit(self):
        with self.assertRaises(PayloadError): validate_catalog([example(), example()], max_definitions=1)
    def test_invalid_direct_dataclass(self):
        with self.assertRaises(PayloadError): validate_catalog([dataclasses.replace(example(), requires_scope=False)])
    def test_non_definition(self):
        with self.assertRaises(TypeError): validate_catalog([object()])
    def test_summary_does_not_contain_template(self):
        d = dataclasses.replace(example(), template='TOP_SECRET_{{nonce}}')
        self.assertNotIn('TOP_SECRET', str(validate_catalog([d]).safe_summary()))
    def test_catalog_integration(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'xss' / 'reflected.yaml'
            path.parent.mkdir()
            path.write_text(yaml.safe_dump({
                'schema_version': 1, 'id': 'INPUT-REFLECTION-001', 'name': 'Marker',
                'category': 'xss', 'payload': {'template': 'muninn_{{nonce}}', 'encoding': 'none'},
                'contexts': ['query'], 'execution': {'mode': 'authorized_active',
                'requires_scope': True, 'requires_active_permission': True, 'max_requests': 1},
                'detection': {'type': 'response_contains_marker', 'confidence': 'informational'},
                'safety': {'destructive': False, 'out_of_band': False, 'requires_manual_review': False},
            }), encoding='utf-8')
            report = PayloadValidator(tmp).validate()
            self.assertEqual(report.definitions, 1)
            self.assertTrue(report.valid)
    def test_empty_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(PayloadValidator(tmp).validate().valid)
    def test_reject_malformed_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'bad.yaml').write_text('foo: [')
            with self.assertRaises(PayloadError): PayloadValidator(tmp).validate()

if __name__ == '__main__': unittest.main()

