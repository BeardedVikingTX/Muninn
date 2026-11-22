import os
import pickle
import tempfile
import unittest
from pathlib import Path
from integrations.credentials import Credentials, CredentialError


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'keys.txt'

    def load(self, text, env=None):
        self.path.write_text(text)
        self.path.chmod(0o600)
        return Credentials.load(self.path, environ=env or {})

    def test_literal_equals(self):
        self.assertEqual(self.load('GROQ_API_KEY=a=b#c').reveal('GROQ_API_KEY'), 'a=b#c')

    def test_duplicate(self):
        with self.assertRaises(CredentialError):
            self.load('GROQ_API_KEY=a\nGROQ_API_KEY=b')

    def test_unknown(self):
        with self.assertRaises(CredentialError):
            self.load('UNKNOWN=secret')

    def test_placeholder(self):
        self.assertFalse(self.load('GROQ_API_KEY=<API_KEY_HERE>').configured('groq'))

    def test_override(self):
        self.assertEqual(self.load('GROQ_API_KEY=a', {'GROQ_API_KEY':'b'}).reveal('GROQ_API_KEY'), 'b')

    def test_empty_override(self):
        self.assertFalse(self.load('GROQ_API_KEY=a', {'GROQ_API_KEY':''}).configured('groq'))

    def test_environment_only(self):
        self.assertTrue(Credentials.load(environ={'NVD_API_KEY':'fake'}).configured('nvd'))

    def test_project_discovery(self):
        self.assertFalse(self.load('PROJECT_DISCOVERY_API_KEY=a').configured('project_discovery'))
        self.assertTrue(self.load('PROJECT_DISCOVERY_API_KEY=a\nPROJECT_DISCOVERY_TEAM_ID=b').configured('project_discovery'))

    def test_permissions(self):
        self.path.write_text('GROQ_API_KEY=a')
        self.path.chmod(0o644)
        with self.assertRaises(CredentialError):
            Credentials.load(self.path, environ={})

    def test_symlink(self):
        self.load('GROQ_API_KEY=a')
        link = self.path.with_name('link')
        link.symlink_to(self.path)
        with self.assertRaises(CredentialError):
            Credentials.load(link, environ={})

    def test_hardlink(self):
        self.load('GROQ_API_KEY=a')
        os.link(self.path, self.path.with_name('link'))
        with self.assertRaises(CredentialError):
            Credentials.load(self.path, environ={})

    def test_masking(self):
        c = self.load('GROQ_API_KEY=unique-secret-123')
        self.assertNotIn('unique-secret-123', repr(c) + repr(c.status()))
        with self.assertRaises(TypeError):
            pickle.dumps(c)

    def test_extra_provider(self):
        c = Credentials.load(environ={'CUSTOM_KEY':'fake'}, extra_providers={'custom':('CUSTOM_KEY',)})
        self.assertTrue(c.configured('custom'))

    def test_control(self):
        with self.assertRaises(CredentialError):
            self.load('GROQ_API_KEY=a\x00b')

    def test_size(self):
        with self.assertRaises(CredentialError):
            self.load('#' * 140000)

    def test_no_expansion(self):
        self.assertEqual(self.load('GROQ_API_KEY=$HOME').reveal('GROQ_API_KEY'), '$HOME')

    def test_missing(self):
        with self.assertRaises(CredentialError):
            Credentials.load(environ={}).reveal('NVD_API_KEY')

if __name__ == '__main__':
    unittest.main()

