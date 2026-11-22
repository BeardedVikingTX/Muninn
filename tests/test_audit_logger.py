import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from core.audit_logger import AuditLogger, AuditLogError


class AuditLoggerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "events.jsonl"
        self.log = AuditLogger(self.path)

    def record(self, **kw):
        return self.log.record("RUN_STARTED", run_id="run1", component="engine", **kw)

    def test_empty(self):
        self.assertTrue(self.log.verify().valid)
        self.assertEqual(self.log.verify().count, 0)

    def test_record_and_verify(self):
        a = self.record(metadata={"count": 2, "status": "ok"})
        b = self.record()
        self.assertEqual((a.sequence, b.sequence), (1, 2))
        self.assertEqual(self.log.verify().count, 2)
        self.assertTrue(self.log.verify().valid)

    def test_private_permissions(self):
        self.record()
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.path.parent / "events.jsonl.lock").stat().st_mode & 0o777, 0o600)

    def test_sensitive_metadata_rejected(self):
        for key in ("password", "cookie", "authorization", "url", "body", "headers", "payload"):
            with self.subTest(key=key), self.assertRaises(AuditLogError):
                self.record(metadata={key: "secret"})
        self.assertEqual(self.log.verify().count, 0)

    def test_freeform_value_rejected(self):
        with self.assertRaises(AuditLogError):
            self.record(metadata={"status": "Bearer abc xyz"})

    def test_invalid_identifiers(self):
        for value in ("../secret", "", "hello world", "https://example.org", "x" * 97):
            with self.subTest(value=value), self.assertRaises(AuditLogError):
                self.log.record("RUN_STARTED", run_id=value, component="core")

    def test_unknown_event(self):
        with self.assertRaises(AuditLogError):
            self.log.record("ARBITRARY", run_id="run", component="core")

    def test_numeric_validation(self):
        for value in (-1, 1.5, True, "3", 10**10):
            with self.subTest(value=value), self.assertRaises(AuditLogError):
                self.record(metadata={"count": value})

    def test_detect_tampering(self):
        self.record()
        data = self.path.read_bytes().replace(b"RUN_STARTED", b"RUN_FINISHED")
        self.path.write_bytes(data)
        self.assertFalse(self.log.verify().valid)
        with self.assertRaises(AuditLogError):
            self.record()

    def test_detect_truncation(self):
        self.record()
        self.path.write_bytes(self.path.read_bytes()[:-4])
        self.assertFalse(self.log.verify().valid)

    def test_detect_deleted_record(self):
        self.record()
        self.record()
        self.path.write_bytes(self.path.read_bytes().splitlines(keepends=True)[1])
        self.assertFalse(self.log.verify().valid)

    def test_detect_reordered_records(self):
        self.record()
        self.record()
        self.path.write_bytes(b"".join(reversed(self.path.read_bytes().splitlines(keepends=True))))
        self.assertFalse(self.log.verify().valid)

    def test_hmac_authentication(self):
        key = b"k" * 32
        a = AuditLogger(self.path, hmac_key=key)
        a.record("RUN_STARTED", run_id="r", component="core")
        self.assertTrue(a.verify().valid)
        self.assertFalse(AuditLogger(self.path, hmac_key=b"z" * 32).verify().valid)
        self.assertFalse(self.log.verify().valid)

    def test_short_key_rejected(self):
        with self.assertRaises(AuditLogError):

