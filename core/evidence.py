"""Muninn evidence preservation and redaction (offline; Python >= 3.10).

Evidence is untrusted and may contain credentials or personal information.
Only redacted text is persisted. Raw bytes are never persisted by this module.
The digest of the original bytes is recorded for local correlation; it does not
prove authenticity or independently establish vulnerability impact.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Mapping
import json
import os
import re
import threading
import uuid

MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_TEXT_CHARS = 256_000
VERSION = "muninn-evidence-v1"

class ArtifactKind(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"
    OBSERVATION = "observation"
    CONTROL = "control"
    OTHER = "other"

class EvidenceError(Exception):
    """An evidence validation or persistence failure."""

# Match common HTTP header secrets, including whitespace variants.
_SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token", "x-access-token",
    "x-csrf-token", "x-xsrf-token", "x-amz-security-token",
})
_SENSITIVE_KEYS = frozenset({
    "password", "passwd", "pwd", "secret", "client_secret", "api_key", "apikey",
    "access_token", "refresh_token", "id_token", "auth_token", "session_token",
    "jwt", "authorization", "cookie", "set_cookie", "private_key", "token",
    "otp", "totp", "verification_code", "reset_token", "code_verifier",
})
_HEADER_RE = re.compile(r"(?im)^(?P<name>[A-Za-z0-9_-]+)(?P<sep>\s*:\s*)(?P<value>[^\r\n]*)$")
_KV_RE = re.compile(r"(?i)(?P<name>\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access_token|refresh_token|id_token|auth_token|session_token|jwt|private_key|token|otp|totp|verification_code|reset_token|code_verifier)\b)(?P<sep>\s*[=:]\s*)(?P<quote>['\"]?)(?P<value>[^\s&;,\r\n'\"}]+)")
_BEARER_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+={0,2}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*\b")
_QUERY_RE = re.compile(r"(?i)([?&](?:password|passwd|pwd|secret|client_secret|api[_-]?key|access_token|refresh_token|id_token|auth_token|session_token|token|jwt|reset_token|code_verifier|otp)=)[^&#\s]+")


def _json_redact(value: object) -> object:
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if str(k).lower().replace("-", "_") in _SENSITIVE_KEYS else _json_redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_redact(v) for v in value]
    return value


def redact_text(text: str) -> str:
    """Best-effort redaction; NOT a guarantee against arbitrary secret formats.

    Callers should avoid passing unnecessary PII. For high-sensitivity traffic,
    disable artifact capture or supply pre-sanitized minimal excerpts.
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")
    # For JSON bodies, redact nested keys while preserving a readable shape.
    if text.lstrip().startswith(("{", "[")):
        try:
            text = json.dumps(_json_redact(json.loads(text)), ensure_ascii=True)
        except (ValueError, TypeError):
            pass
    def redact_header(match: re.Match[str]) -> str:
        if match.group("name").lower() in _SENSITIVE_HEADERS:
            return f'{match.group("name")}{match.group("sep")}[REDACTED]'
        return match.group(0)
    text = _HEADER_RE.sub(redact_header, text)
    text = _QUERY_RE.sub(r"\1[REDACTED]", text)
    text = _KV_RE.sub(lambda m: f'{m.group("name")}{m.group("sep")}{m.group("quote")}[REDACTED]', text)
    text = _BEARER_RE.sub(lambda m: f'{m.group(1)} [REDACTED]', text)
    text = _JWT_RE.sub("[REDACTED_JWT]", text)
    return text


def _safe_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise ValueError(f"{label} must be 1-128 safe ASCII characters")
    if value in (".", "..") or ".." in value:
        raise ValueError(f"{label} cannot contain '..'")
    return value


def _metadata(value: Mapping[str, str]) -> dict[str, str]:
    if len(value) > 32:
        raise EvidenceError("too many metadata entries")
    result = {}
    for k, v in value.items():
        if not isinstance(k, str) or not isinstance(v, str) or len(k) > 80 or len(v) > 1000:
            raise EvidenceError("metadata keys/values must be short strings")
        result[k] = "[REDACTED]" if k.lower().replace("-", "_") in _SENSITIVE_KEYS else redact_text(v)
    return result


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: str
    finding_id: str
    kind: ArtifactKind
    source_id: str
    captured_at: str
    original_sha256: str
    original_size: int
    excerpt_sha256: str
    excerpt_path: str
    truncated: bool
    metadata: Mapping[str, str] = field(default_factory=dict)
    schema_version: str = VERSION

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "evidence_id": self.evidence_id,
            "finding_id": self.finding_id,
            "kind": self.kind.value,
            "source_id": self.source_id,
            "captured_at": self.captured_at,
            "original_sha256": self.original_sha256,
            "original_size": self.original_size,
            "excerpt_sha256": self.excerpt_sha256,
            "excerpt_path": self.excerpt_path,
            "truncated": self.truncated,
            "metadata": dict(sorted(self.metadata.items())),
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), sort_keys=True, ensure_ascii=True)


class EvidenceStore:
    """Write-only evidence store with atomic files and restrictive permissions.

    The output directory must be private and trusted. Concurrent threads are
    supported within one process; separate processes must use separate stores.
    """

    def __init__(self, root: str | Path, *, max_artifact_bytes: int = MAX_ARTIFACT_BYTES):
        self.root = Path(root).resolve()
        if not isinstance(max_artifact_bytes, int) or not 0 < max_artifact_bytes <= MAX_ARTIFACT_BYTES:
            raise ValueError("invalid max_artifact_bytes")
        self.max_artifact_bytes = max_artifact_bytes
        self._lock = threading.Lock()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink() or not self.root.is_dir():
            raise EvidenceError("evidence root must be a directory")
        os.chmod(self.root, 0o700)

    def capture(self, *, finding_id: str, source_id: str, kind: ArtifactKind,
                content: bytes | str, metadata: Mapping[str, str] | None = None,
                evidence_id: str | None = None) -> EvidenceRecord:
        _safe_id(finding_id, "finding_id")
        _safe_id(source_id, "source_id")
        if not isinstance(kind, ArtifactKind):
            raise TypeError("kind must be ArtifactKind")
        eid = _safe_id(evidence_id or uuid.uuid4().hex, "evidence_id")
        if isinstance(content, str):
            raw = content.encode("utf-8", errors="replace")
        elif isinstance(content, bytes):
            raw = content
        else:
            raise TypeError("content must be bytes or str")
        if len(raw) > self.max_artifact_bytes:
            raise EvidenceError("artifact exceeds size limit; supply a bounded excerpt")
        # Binary bodies can contain sensitive data; never try to persist them as text.
        binary = b"\x00" in raw or any(b < 9 or 13 < b < 32 for b in raw[:4096])
        if binary:
            excerpt = "[BINARY CONTENT OMITTED]"
            truncated = True
        else:
            decoded = raw.decode("utf-8", errors="replace")
            truncated = len(decoded) > MAX_TEXT_CHARS
            excerpt = redact_text(decoded[:MAX_TEXT_CHARS])
            if truncated:
                excerpt += "\n[TRUNCATED]"
        encoded = excerpt.encode("utf-8")
        info = _metadata(metadata or {})
        record = EvidenceRecord(
            evidence_id=eid, finding_id=finding_id, kind=kind,
            source_id=source_id,
            captured_at=datetime.now(timezone.utc).isoformat(),
            original_sha256=sha256(raw).hexdigest(), original_size=len(raw),
            excerpt_sha256=sha256(encoded).hexdigest(),
            excerpt_path=f"{eid}.txt", truncated=truncated, metadata=info,
        )
        with self._lock:
            # Exclusive creation prevents overwriting evidence and symlink following.
            text_path = self.root / f"{eid}.txt"
            json_path = self.root / f"{eid}.json"
            if text_path.exists() or json_path.exists() or text_path.is_symlink() or json_path.is_symlink():
                raise EvidenceError("evidence ID already exists")
            created: list[Path] = []
            try:
                for path, payload in ((text_path, encoded), (json_path, record.to_json().encode("utf-8"))):
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    fd = os.open(path, flags, 0o600)
                    created.append(path)
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(payload)
                        handle.flush()
                        os.fsync(handle.fileno())
            except Exception:
                for path in created:
                    path.unlink(missing_ok=True)
                raise
        return record

    def verify(self, record: EvidenceRecord) -> bool:
        """Check saved redacted excerpt against its manifest digest."""
        _safe_id(record.evidence_id, "evidence_id")
        path = self.root / f"{record.evidence_id}.txt"
        if path.is_symlink() or not path.is_file():
            return False
        try:
            data = path.read_bytes()
        except OSError:
            return False
        return sha256(data).hexdigest() == record.excerpt_sha256


def confidence_evidence(record: EvidenceRecord, *, kind: str = "indicator",
                        quality: str = "medium", independence_key: str = ""):
    """Optional adapter to core.confidence without making confidence a dependency.

    Validation flags are intentionally not inferred from a saved artifact.
    """
    from core.confidence import Evidence, EvidenceKind, EvidenceQuality
    return Evidence(
        evidence_id=record.evidence_id,
        kind=EvidenceKind(kind),
        quality=EvidenceQuality(quality),
        independence_key=independence_key or record.source_id,
        fingerprint=record.original_sha256,
        description=f"Redacted {record.kind.value} evidence from {record.source_id}",
    )
