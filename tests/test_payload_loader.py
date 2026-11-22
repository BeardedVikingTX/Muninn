import dataclasses
import os
from pathlib import Path
import tempfile
import unittest

from core.payload_loader import PayloadLoader, PayloadError, validate_payload


def valid():
    return {'schema_version': 1, 'id': 'INPUT-REFLECTION-001', 'name': 'Reflection probe',
            'category': 'xss', 'description': 'Harmless marker',
            'payload': {'template': 'muninn_probe_{{nonce}}', 'encoding': 'none'},
            'contexts': ['query', 'form'],
            'execution': {'mode': 'authorized_active', 'requires_scope': True,
                          'requires_active_permission': True, 'max_requests': 1},
            'detection': {'type': 'response_contains_marker', 'confidence': 'informational'},
            'safety': {'destructive': False, 'out_of_band': False, 'requires_manual_review': False}}


class PayloadLoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, text, filename='xss/reflection.yaml'):
        path = self.root / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def test_valid_definition(self):
        d = validate_payload(valid())
        self.assertEqual(d.id, 'INPUT-REFLECTION-001')
        self.assertEqual(d.contexts, ('query', 'form'))

    def test_immutable(self):
        d = validate_payload(valid())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            d.template = 'changed'

    def test_safe_summary_excludes_template(self):
        d = validate_payload(valid())
        self.assertNotIn('template', str(d.safe_summary()))
        self.assertNotIn('muninn_probe', str(d.safe_summary()))

    def test_context_selection(self):
        d = validate_payload(valid())
        point = type('Point', (), {'location': 'query'})()
        self.assertTrue(d.compatible_with(point))
        point.location = 'header'
        self.assertFalse(d.compatible_with(point))

    def test_empty_placeholder(self):
        self.write('')
        self.assertEqual(PayloadLoader(self.root).load(), ())

    def test_valid_yaml(self):
        self.write('''schema_version: 1
id: INPUT-REFLECTION-001
name: Reflection probe
category: xss
payload:
  template: "muninn_probe_{{nonce}}"
  encoding: none
contexts: [query, form]
execution:
  mode: authorized_active
  requires_scope: true
  requires_active_permission: true
  max_requests: 1
detection:
  type: response_contains_marker
  confidence: informational
safety:
  destructive: false
  out_of_band: false
  requires_manual_review: false
''')
        self.assertEqual(len(PayloadLoader(self.root).load()), 1)

    def test_duplicate_mapping_key(self):
        self.write('id: FIRST\nid: SECOND\n')
        with self.assertRaises(PayloadError):
            PayloadLoader(self.root).load()

    def test_alias_rejected(self):
        self.write('a: &anchor [1]\nb: *anchor\n')
        with self.assertRaises(PayloadError):
            PayloadLoader(self.root).load()

    def test_custom_tag_rejected(self):
        self.write('!!python/object/apply:os.system ["echo no"]')
        with self.assertRaises(PayloadError):
            PayloadLoader(self.root).load()

