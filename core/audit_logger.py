"""Muninn append-only, privacy-first operational audit journal (POSIX).

Only allowlisted metadata may be logged. Never store HTTP bodies, headers,
credentials, payloads, or evidence here. This module does not authorize tests.

Integrity: SHA-256 chained records, optionally HMAC-SHA256 using a separately
protected secret. A hash chain alone cannot prevent an attacker rewriting the
whole journal. Keep external checkpoints for stronger rollback detection.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

__all__ = ["AuditLogger", "AuditLogError", "IntegrityReport", "AuditEvent"]

_ZERO = "0" * 64
_IDENT = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,95}$")
_EVENTS = frozenset({
    "RUN_STARTED", "RUN_FINISHED", "REQUEST_IMPORTED", "SCOPE_APPROVED",
    "SCOPE_DENIED", "INJECTION_POINT_DISCOVERED", "PAYLOAD_VALIDATED",
    "PAYLOAD_REJECTED", "TEST_SKIPPED", "TEST_STARTED", "TEST_EXECUTED",
    "TEST_FAILED", "EVIDENCE_RECORDED", "FINDING_CREATED", "FINDING_UPDATED",
    "SYSTEM_ERROR", "POLICY_DENIED", "QUOTA_DENIED", "INTEGRITY_CHECK",
})
# Values must be identifiers, enum-like states or small counts, never user input.
_FIELDS = frozenset({
    "decision", "reason_code", "status", "outcome", "http_status", "count",
    "duration_ms", "attempt", "point_count", "finding_count", "rule_id",
    "payload_id", "point_id", "source_id", "evidence_id", "finding_id",
    "policy_id", "scope_rule_id", "worker_id", "adapter_id", "error_code",
})
_NUMERIC = frozenset({"http_status", "count", "duration_ms", "attempt", "point_count", "finding_count"})


class AuditLogError(RuntimeError):
    """An audit event could not be written or verified safely."""


@dataclass(frozen=True, slots=True)
class AuditEvent:
    sequence: int
    event_type: str
    run_id: str
    correlation_id: str
    component: str
    timestamp: str
    digest: str


@dataclass(frozen=True, slots=True)
class IntegrityReport:
    valid: bool
    count: int
    last_digest: str
    error: str | None = None


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _id(value: str, name: str) -> str:
    if not isinstance(value, str) or not _IDENT.fullmatch(value):
        raise AuditLogError(f"invalid {name}: expected a short opaque identifier")
    return value


def _metadata(values: Mapping | None) -> dict:
    if values is None:
        return {}
    if not isinstance(values, Mapping) or len(values) > 24:
        raise AuditLogError("invalid metadata")
    result = {}
    for key, value in values.items():
        if not isinstance(key, str) or key not in _FIELDS:
            raise AuditLogError("metadata field not allowlisted")
        if key in _NUMERIC:
            if type(value) is not int or value < 0 or value > 10**9:
                raise AuditLogError("invalid numeric metadata")
        else:
            _id(value, "metadata value")
        result[key] = value
    return result


def _open_regular(path: Path, flags: int, mode: int = 0o600) -> int:
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, mode)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise AuditLogError("audit path is not a private regular file")
        if st.st_mode & 0o077:
            raise AuditLogError("audit file permissions must be 0600 or stricter")
        return fd
    except BaseException:
        os.close(fd)
        raise


class AuditLogger:
    """Synchronous process-safe journal; Linux/POSIX fcntl locking required.

    The directory must already exist and be owned/trusted by the operator.
    Use a unique journal per engagement. For fail-closed operations, invoke
    ``record`` *before* the operation and abort if it raises AuditLogError.
    """

    def __init__(self, path: str | os.PathLike, *, hmac_key: bytes | None = None,
                 max_bytes: int = 64 * 1024 * 1024, sync: bool = True):
        self.path = Path(path)
        if self.path.name in {"", ".", ".."} or self.path.is_dir():
            raise AuditLogError("expected a journal filename")
        if not self.path.parent.is_dir() or self.path.parent.is_symlink():
            raise AuditLogError("journal directory must already exist and not be a symlink")
        if hmac_key is not None and (not isinstance(hmac_key, bytes) or len(hmac_key) < 32):
            raise AuditLogError("HMAC key must contain at least 32 bytes")
        if type(max_bytes) is not int or not 4096 <= max_bytes <= 2**31:
            raise AuditLogError("invalid journal size limit")
        self._key = hmac_key
        self._max_bytes = max_bytes
        self._sync = bool(sync)
        self._mutex = threading.RLock()
        self._lock_path = self.path.with_name(self.path.name + ".lock")

    def _digest(self, record: dict) -> str:
        data = _canonical(record)
        return (hmac.new(self._key, data, hashlib.sha256).hexdigest()
                if self._key is not None else hashlib.sha256(data).hexdigest())

    def _verify_fd(self, fd: int) -> IntegrityReport:
        os.lseek(fd, 0, os.SEEK_SET)
        previous = _ZERO
        count = 0
        with os.fdopen(os.dup(fd), "rb") as stream:
            for line in stream:
                if len(line) > 16384:
                    return IntegrityReport(False, count, previous, "oversized record")
                if not line.endswith(b"\n"):
                    return IntegrityReport(False, count, previous, "incomplete record")
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError()
                    digest = record.pop("digest")
                    if set(record) != {"version", "sequence", "timestamp", "event_type", "run_id", "correlation_id", "component", "metadata", "previous_digest"}:
                        raise ValueError()
                    if record["version"] != 1 or type(record["sequence"]) is not int or record["sequence"] != count + 1:
                        raise ValueError()
                    if record["previous_digest"] != previous:
                        return IntegrityReport(False, count, previous, "broken chain")
                    _id(record["event_type"], "event type")
                    if record["event_type"] not in _EVENTS:
                        raise ValueError()
                    for field in ("run_id", "correlation_id", "component"):
                        _id(record[field], field)
                    _metadata(record["metadata"])
                    if not isinstance(record["timestamp"], str) or len(record["timestamp"]) > 40:
                        raise ValueError()
                    if not isinstance(digest, str) or not hmac.compare_digest(self._digest(record), digest):
                        return IntegrityReport(False, count, previous, "digest mismatch")
                except (ValueError, KeyError, TypeError, AuditLogError, UnicodeDecodeError):
                    return IntegrityReport(False, count, previous, "malformed record")
                previous = digest
                count += 1
        return IntegrityReport(True, count, previous)

    def _locked(self):
        """Open lock fd; caller must unlock and close in finally."""
        fd = _open_regular(self._lock_path, os.O_RDWR | os.O_CREAT)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def verify(self) -> IntegrityReport:
        with self._mutex:
            lock = self._locked()
            try:
                try:
                    fd = _open_regular(self.path, os.O_RDONLY)
                except FileNotFoundError:
                    return IntegrityReport(True, 0, _ZERO)
                try:
                    return self._verify_fd(fd)
                finally:
                    os.close(fd)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
                os.close(lock)

    def record(self, event_type: str, *, run_id: str, component: str,
               correlation_id: str | None = None,
               metadata: Mapping | None = None) -> AuditEvent:
        _id(event_type, "event type")
        if event_type not in _EVENTS:
            raise AuditLogError("unsupported event type")
        _id(run_id, "run id")
        _id(component, "component")
        correlation_id = _id(correlation_id or uuid.uuid4().hex, "correlation id")
        clean = _metadata(metadata)
        with self._mutex:
            lock = self._locked()
            try:
                fd = _open_regular(self.path, os.O_RDWR | os.O_CREAT)
                try:
                    report = self._verify_fd(fd)
                    if not report.valid:
                        raise AuditLogError("existing audit journal failed integrity verification: " + (report.error or "unknown"))
                    record = {
                        "version": 1,
                        "sequence": report.count + 1,
                        "timestamp": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                        "event_type": event_type,
                        "run_id": run_id,
                        "correlation_id": correlation_id,
                        "component": component,
                        "metadata": clean,
                        "previous_digest": report.last_digest,
                    }
                    digest = self._digest(record)
                    line = _canonical({**record, "digest": digest}) + b"\n"
                    end = os.lseek(fd, 0, os.SEEK_END)
                    if end + len(line) > self._max_bytes:
                        raise AuditLogError("journal size limit reached; archive and checkpoint before continuing")
                    # One write while holding the inter-process lock. A partial write
                    # is detectable and blocks future events until operator recovery.
                    if os.write(fd, line) != len(line):
                        raise AuditLogError("incomplete audit write")
                    if self._sync:
                        os.fsync(fd)
                    return AuditEvent(report.count + 1, event_type, run_id,
                                      correlation_id, component, record["timestamp"], digest)
                finally:
                    os.close(fd)
            except OSError as exc:
                raise AuditLogError("audit I/O failure") from exc
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
                os.close(lock)
