import json
import unittest
from dataclasses import replace
from audit.sqli import SQLiAuditor, SQLiConfig, SQLiObservation

URL = 'https://app.example.test/search?q=private-token'
SCOPE = lambda url: url.startswith('https://app.example.test/')


def obs(**kwargs):
    return SQLiObservation(url=URL, parameter='search', **kwargs)


class SQLiTests(unittest.TestCase):
    def setUp(self):
        self.auditor = SQLiAuditor()

    def kinds(self, items):
        return {f.kind for f in self.auditor.analyze(items, scope_check=SCOPE).findings}

    def test_no_findings_on_clean_input(self):
        self.assertFalse(self.kinds([obs(status=200, response_text='ok')]))

    def test_mysql_error(self):
        self.assertIn('sql_error_signature', self.kinds([obs(response_text='You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version')]))

    def test_postgres_error(self):
        self.assertIn('sql_error_signature', self.kinds([obs(response_text='PG::SyntaxError')]))

    def test_mssql_error(self):
        self.assertIn('sql_error_signature', self.kinds([obs(response_text='Unclosed quotation mark after the character string')]))

    def test_oracle_error(self):
        self.assertIn('sql_error_signature', self.kinds([obs(response_text='ORA-00933')]))

    def test_sqlite_error(self):
        self.assertIn('sql_error_signature', self.kinds([obs(response_text='SQLite error: near X: syntax error')]))

    def test_baseline_error_suppresses(self):
        msg = 'ORA-00933'
        self.assertNotIn('sql_error_signature', self.kinds([obs(variant='baseline', response_text=msg), obs(response_text=msg)]))

    def test_verified_effect_requires_reference(self):
        with self.assertRaises(ValueError):
            self.auditor.analyze([obs(verified_db_effect=True)], scope_check=SCOPE)

    def test_verified_effect(self):
        self.assertIn('trusted_database_effect', self.kinds([obs(verified_db_effect=True, verification_reference='internal-fixture-1')]))

    def test_boolean_difference(self):
        items = [obs(variant='boolean_true', response_fingerprint='yes') for _ in range(3)] + [obs(variant='boolean_false', response_fingerprint='no') for _ in range(3)]
        self.assertIn('boolean_response_differential', self.kinds(items))

    def test_boolean_same_not_finding(self):
        items = [obs(variant='boolean_true', response_fingerprint='same') for _ in range(3)] + [obs(variant='boolean_false', response_fingerprint='same') for _ in range(3)]
        self.assertNotIn('boolean_response_differential', self.kinds(items))

    def test_boolean_inconsistent_not_finding(self):
        items = [obs(variant='boolean_true', response_fingerprint=x) for x in ('yes', 'different')] + [obs(variant='boolean_false', response_fingerprint='no') for _ in range(2)]
        self.assertNotIn('boolean_response_differential', self.kinds(items))

    def test_boolean_insufficient_samples(self):
        self.assertNotIn('boolean_response_differential', self.kinds([obs(variant='boolean_true', response_fingerprint='yes'), obs(variant='boolean_false', response_fingerprint='no')]))

    def test_timing_differential(self):
        items = [obs(variant='timing_control', elapsed_ms=100+i) for i in range(6)] + [obs(variant='timing_candidate', elapsed_ms=2100+i) for i in range(6)]
        self.assertIn('timing_differential', self.kinds(items))

    def test_timing_jitter_suppressed(self):
        items = [obs(variant='timing_control', elapsed_ms=x) for x in (10, 100, 200, 700, 800, 1000)] + [obs(variant='timing_candidate', elapsed_ms=3000+i) for i in range(6)]
        self.assertNotIn('timing_differential', self.kinds(items))

    def test_timing_small_delta_suppressed(self):
        items = [obs(variant='timing_control', elapsed_ms=100+i) for i in range(6)] + [obs(variant='timing_candidate', elapsed_ms=150+i) for i in range(6)]
        self.assertNotIn('timing_differential', self.kinds(items))

    def test_timing_negative_rejected(self):
        with self.assertRaises(ValueError):
            self.auditor.analyze([obs(elapsed_ms=-1)], scope_check=SCOPE)

    def test_timing_nan_rejected(self):
        with self.assertRaises(ValueError):
            self.auditor.analyze([obs(elapsed_ms=float('nan'))], scope_check=SCOPE)

    def test_out_of_scope_excluded(self):
        report = self.auditor.analyze([replace(obs(response_text='ORA-00933'), url='https://other.example/')], scope_check=SCOPE)
        self.assertEqual((report.analyzed, report.excluded_out_of_scope, len(report.findings)), (0, 1, 0))

    def test_scope_callback_mandatory(self):
        with self.assertRaises(TypeError):
            self.auditor.analyze([obs()], scope_check=None)

    def test_scope_callback_exception_fails_closed(self):
        with self.assertRaises(RuntimeError):
            self.auditor.analyze([obs()], scope_check=lambda _: (_ for _ in ()).throw(RuntimeError('policy failure')))

