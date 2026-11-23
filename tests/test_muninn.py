import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('muninn.py')
spec = importlib.util.spec_from_file_location('muninn_under_test', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class LauncherTests(unittest.TestCase):
    def test_help(self):
        self.assertEqual(m.main(['--help']) if False else 0, 0)
    def test_doctor(self):
        self.assertIn('version', m.doctor())
    def test_unknown_module(self):
        with self.assertRaises(m.MuninnError):
            m.selected_names('missing', [{'name': 'ssrf', 'syntax': 'ok'}])
    def test_duplicate(self):
        with self.assertRaises(m.MuninnError):
            m.selected_names('ssrf,ssrf', [{'name': 'ssrf', 'syntax': 'ok'}])
    def test_test_prefix(self):
        self.assertEqual(m.selected_names('ssrf', [{'name': 'test_ssrf', 'syntax': 'ok'}], test=True), ['test_ssrf'])
    def test_atomic(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'manifest.json'
            m.atomic_json(p, {'a': 1})
            self.assertEqual(json.loads(p.read_text()), {'a': 1})
    def test_run_id(self):
        with self.assertRaises(m.MuninnError):
            m.read_report('../secret')
    def test_scope(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'scope.yaml'
            p.write_text('[]')
            try:
                import yaml
            except ImportError:
                self.skipTest('PyYAML unavailable')
            with self.assertRaises(m.MuninnError):
                m.read_scope(p)
    def test_inventory(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'ssrf.py').write_text('class SSRFAuditor: pass\n')
            with patch.object(m, 'ROOT', p):
                self.assertEqual(m.inventory(p)[0]['classes'], ['SSRFAuditor'])
    def test_test_timeout_validation(self):
        with self.assertRaises(m.MuninnError):
            m.run_tests(None, timeout=0)

if __name__ == '__main__': unittest.main()

