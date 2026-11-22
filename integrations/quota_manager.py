"""Offline, persistent API budget admission control. Python 3.10+.
Fixed UTC windows; rolling request-rate window; explicit lease completion.
Budgets count attempts, including failures. Token reservations are not refunded.
Use one private database per installation. No network operations.
"""
from __future__ import annotations
from dataclasses import dataclass
from contextlib import contextmanager
import math
import os
import re
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Mapping, Callable


@dataclass(frozen=True)
class QuotaPolicy:
    requests_per_minute: int
    requests_per_day: int
    max_concurrent: int
    tokens_per_day: int = 0
    lease_seconds: int = 300

    def __post_init__(self):
        for name in ('requests_per_minute', 'requests_per_day', 'max_concurrent', 'tokens_per_day', 'lease_seconds'):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 10**9:
                raise ValueError(f'invalid policy field: {name}')
        if not 1 <= self.lease_seconds <= 86400:
            raise ValueError('lease_seconds must be between 1 and 86400')


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    lease_id: str | None = None
    retry_after: float | None = None
    expires_at: float | None = None


class QuotaManager:
    """SQLite serializes reservations across workers sharing a local database.

    Parent directory must be private and trusted. All workers must use identical
    policies. Caller must finish each lease and bound request runtime below its
    lifetime. A crashed worker's slot expires; charged attempts remain charged.
    """
    def __init__(self, path: str | Path, policies: Mapping[str, QuotaPolicy], *, clock: Callable[[], float] = time.time):
        self.path = Path(path).absolute()
        self.policies = dict(policies)
        self.clock = clock
        for name, policy in self.policies.items():
            if not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', name) or not isinstance(policy, QuotaPolicy):
                raise ValueError('invalid provider policy')
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == 'posix':
            st = self.path.parent.stat()
            if st.st_uid != os.getuid() or st.st_mode & 0o077 or self.path.parent.is_symlink():
                raise PermissionError('quota database requires private owned directory')
        import stat
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0), 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise PermissionError('invalid database file')
            if os.name == 'posix' and (st.st_uid != os.getuid() or st.st_mode & 0o077):
                raise PermissionError('insecure quota database permissions')
        finally:
            os.close(fd)
        with self._transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY, provider TEXT NOT NULL, ts REAL NOT NULL, tokens INTEGER NOT NULL, expires REAL NOT NULL, finished INTEGER NOT NULL DEFAULT 0)')
            db.execute('CREATE INDEX IF NOT EXISTS attempts_provider_ts ON attempts(provider,ts)')
            db.execute('CREATE TABLE IF NOT EXISTS cooldown (provider TEXT PRIMARY KEY, until REAL NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS clock_state (id INTEGER PRIMARY KEY CHECK(id=1), last REAL NOT NULL)')

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _now(self, db):
        now = float(self.clock())
        if not math.isfinite(now) or not 0 <= now < 10**11:
            raise ValueError('invalid clock')
        row = db.execute('SELECT last FROM clock_state WHERE id=1').fetchone()
        if row and now < row[0]:
            raise RuntimeError('clock moved backwards; quota admission stopped')
        db.execute('INSERT OR REPLACE INTO clock_state VALUES (1,?)', (now,))
        return now

    def reserve(self, provider: str, *, estimated_tokens: int = 0) -> Decision:
        if type(estimated_tokens) is not int or not 0 <= estimated_tokens <= 10**9:
            raise ValueError('invalid token reservation')
        p = self.policies.get(provider)
        if p is None:
            return Decision(False, 'unknown_provider')
        with self._transaction() as db:
            now = self._now(db)
            start = math.floor(now / 86400) * 86400
            if not (p.requests_per_minute and p.requests_per_day and p.max_concurrent):
                return Decision(False, 'disabled')
            row = db.execute('SELECT until FROM cooldown WHERE provider=?', (provider,)).fetchone()
            if row and row[0] > now:
                return Decision(False, 'cooldown', retry_after=row[0]-now)
            count, tokens = db.execute('SELECT COUNT(*), COALESCE(SUM(tokens),0) FROM attempts WHERE provider=? AND ts>=?', (provider,start)).fetchone()
            if count >= p.requests_per_day:
                return Decision(False, 'daily_requests', retry_after=start+86400-now)
            if estimated_tokens > p.tokens_per_day or tokens + estimated_tokens > p.tokens_per_day:
                return Decision(False, 'daily_tokens', retry_after=None if estimated_tokens > p.tokens_per_day else start+86400-now)
            count, oldest = db.execute('SELECT COUNT(*), MIN(ts) FROM attempts WHERE provider=? AND ts>?', (provider,now-60)).fetchone()
            if count >= p.requests_per_minute:
                return Decision(False, 'minute_requests', retry_after=max(0,oldest+60-now))
            count, expiry = db.execute('SELECT COUNT(*), MIN(expires) FROM attempts WHERE provider=? AND finished=0 AND expires>?', (provider,now)).fetchone()
            if count >= p.max_concurrent:
                return Decision(False, 'concurrency', retry_after=expiry-now)
            lease = uuid.uuid4().hex
            expiry = now+p.lease_seconds
            db.execute('INSERT INTO attempts VALUES (?,?,?,?,?,0)', (lease,provider,now,estimated_tokens,expiry))
            return Decision(True, 'reserved', lease, expires_at=expiry)

    def finish(self, lease_id: str, *, actual_tokens: int | None = None) -> bool:
        """Release slot; record excess token usage; never refund reservations."""
        if actual_tokens is not None and (type(actual_tokens) is not int or not 0 <= actual_tokens <= 10**9):
            raise ValueError('invalid actual token count')
        with self._transaction() as db:
            self._now(db)
            cur = db.execute('UPDATE attempts SET finished=1, tokens=MAX(tokens,?) WHERE id=? AND finished=0', (actual_tokens or 0,lease_id))
            return cur.rowcount == 1

    def cooldown(self, provider: str, seconds: float) -> None:
        if provider not in self.policies:
            raise ValueError('unknown provider')
        if not math.isfinite(seconds) or not 0 <= seconds <= 86400*30:
            raise ValueError('invalid cooldown')
        with self._transaction() as db:
            now = self._now(db)
            db.execute('INSERT INTO cooldown VALUES (?,?) ON CONFLICT(provider) DO UPDATE SET until=MAX(until,excluded.until)', (provider,now+seconds))

    def status(self, provider: str) -> dict:
        if provider not in self.policies:
            raise ValueError('unknown provider')
        with self._transaction() as db:
            now = self._now(db)
            start = math.floor(now/86400)*86400
            count, tokens = db.execute('SELECT COUNT(*),COALESCE(SUM(tokens),0) FROM attempts WHERE provider=? AND ts>=?', (provider,start)).fetchone()
            active = db.execute('SELECT COUNT(*) FROM attempts WHERE provider=? AND finished=0 AND expires>?', (provider,now)).fetchone()[0]
            return {'provider':provider,'daily_requests':count,'daily_tokens':tokens,'active_leases':active}

    def prune(self) -> int:
        """Remove expired historical records outside current day/rate window."""
        with self._transaction() as db:
            now = self._now(db)
            cutoff = min(math.floor(now/86400)*86400,now-60)
            return db.execute('DELETE FROM attempts WHERE ts<? AND expires<=?', (cutoff,now)).rowcount
