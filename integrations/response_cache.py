"""Offline cache for explicitly approved public JSON intelligence.
Never supply credentials, private prompts, or captured HTTP traffic.
Logical payload limits are not exact filesystem quotas. Linux local filesystem only.
"""
from __future__ import annotations
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass

class CacheError(ValueError):
    pass

_NAME = re.compile(r'[a-z][a-z0-9_-]{0,63}\Z')
_SECRET = re.compile(r'authorization|cookie|password|secret|api[_-]?key|access[_-]?token|refresh[_-]?token', re.I)

def _name(value):
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise CacheError('Invalid namespace')
    return value

def _json(value, limit):
    # Defense in depth only: callers must classify data before caching.
    def check(v, depth=0):
        if depth > 40:
            raise CacheError('JSON nesting too deep')
        if isinstance(v, dict):
            for k, x in v.items():
                if not isinstance(k, str) or _SECRET.search(k):
                    raise CacheError('Disallowed JSON field')
                check(x, depth+1)
        elif isinstance(v, (list, tuple)):
            for x in v: check(x, depth+1)
        elif isinstance(v, str):
            if re.search(r'\bBearer\s+\S+|-----BEGIN .*PRIVATE KEY-----', v, re.I):
                raise CacheError('Disallowed JSON content')
        elif v is not None and not isinstance(v, (bool, int, float)):
            raise CacheError('Unsupported JSON value')
    try:
        check(value)
        data = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise CacheError('Invalid or disallowed JSON') from None
    if len(data) > limit:
        raise CacheError('JSON size limit exceeded')
    return data

@dataclass(frozen=True, slots=True)
class CacheKey:
    provider: str
    digest: str
    def __post_init__(self):
        _name(self.provider)
        if not isinstance(self.digest, str) or not re.fullmatch(r'[0-9a-f]{64}', self.digest):
            raise CacheError('Invalid digest')

@dataclass(frozen=True, slots=True)
class CacheHit:
    value: object
    stored_at: float
    expires_at: float

class ResponseCache:
    def __init__(self, path, *, max_bytes=32*1024*1024, max_entries=10000, max_entry_bytes=1024*1024, clock=time.time):
        for v in (max_bytes, max_entries, max_entry_bytes):
            if type(v) is not int or not 0 < v <= 2**31:
                raise CacheError('Invalid cache limit')
        if max_entry_bytes > max_bytes: raise CacheError('Entry exceeds total limit')
        self.path = Path(path).absolute()
        self.max_bytes, self.max_entries, self.max_entry_bytes = max_bytes, max_entries, max_entry_bytes
        self.clock = clock
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        s = self.path.parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
            raise CacheError('Cache requires a private owned directory')
        fd = os.open(self.path, os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK, 0o600)
        try:
            s = os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077 or s.st_nlink != 1:
                raise CacheError('Unsafe cache file')
        finally: os.close(fd)
        with self._tx() as db:
            db.execute('CREATE TABLE IF NOT EXISTS entries (provider TEXT NOT NULL, digest TEXT NOT NULL, payload BLOB NOT NULL, checksum TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, accessed REAL NOT NULL, PRIMARY KEY(provider,digest))')
            db.execute('CREATE INDEX IF NOT EXISTS expiry ON entries(expires)')
            db.execute('CREATE INDEX IF NOT EXISTS lru ON entries(accessed,created,provider,digest)')
            db.execute('CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY CHECK(id=1), last_time REAL NOT NULL)')
            self._prune(db, self._now(db))

    @contextmanager
    def _tx(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally: db.close()

    def _now(self, db):
        n = self.clock()
        if not isinstance(n, (int,float)) or not math.isfinite(n) or n < 0: raise CacheError('Invalid clock')
        old = db.execute('SELECT last_time FROM meta WHERE id=1').fetchone()
        if old and n < old[0]:
            # Invalidate on wall clock rollback, rather than extend freshness.
            db.execute('DELETE FROM entries')
        db.execute('INSERT OR REPLACE INTO meta VALUES(1,?)',(n,))
        return n

    @staticmethod
    def key(provider, operation, parameters, *, version='v1', public=False):
        if public is not True: raise CacheError('Explicit public-data classification required')
        _name(provider); _name(operation); _name(version)
        data = _json([provider,operation,version,parameters], 65536)
        return CacheKey(provider, hashlib.sha256(data).hexdigest())

    def _prune(self, db, now):
        db.execute('DELETE FROM entries WHERE expires <= ?', (now,))
        count, total = db.execute('SELECT count(*), coalesce(sum(length(payload)),0) FROM entries').fetchone()
        if count > self.max_entries or total > self.max_bytes:
            rows = db.execute('SELECT provider,digest,length(payload) FROM entries ORDER BY accessed,created,provider,digest').fetchall()
            for p,k,size in rows:
                if count <= self.max_entries and total <= self.max_bytes: break
                db.execute('DELETE FROM entries WHERE provider=? AND digest=?',(p,k))
                count -= 1; total -= size

    def put(self, key: CacheKey, value, *, ttl: float, public=False):
        if public is not True: raise CacheError('Explicit public-data classification required')
        if not isinstance(key, CacheKey): raise CacheError('Invalid key')
        if type(ttl) not in (int,float) or not math.isfinite(ttl) or not 0 < ttl <= 365*86400: raise CacheError('Invalid TTL')
        payload = _json(value, self.max_entry_bytes)
        with self._tx() as db:
            n = self._now(db)
            db.execute('INSERT OR REPLACE INTO entries VALUES(?,?,?,?,?,?,?)', (key.provider,key.digest,payload,hashlib.sha256(payload).hexdigest(),n,n+ttl,n))
            self._prune(db,n)

    def get(self, key: CacheKey):
        if not isinstance(key, CacheKey): raise CacheError('Invalid key')
        with self._tx() as db:
            n = self._now(db)
            row = db.execute('SELECT payload,checksum,created,expires FROM entries WHERE provider=? AND digest=?',(key.provider,key.digest)).fetchone()
            if row is None: return None
            payload, checksum, created, expires = row
            try:
                if expires <= n or len(payload)>self.max_entry_bytes or hashlib.sha256(payload).hexdigest()!=checksum: raise ValueError
                value = json.loads(payload)
                _json(value,self.max_entry_bytes)
            except (ValueError, TypeError, RecursionError):
                db.execute('DELETE FROM entries WHERE provider=? AND digest=?',(key.provider,key.digest))
                return None
            db.execute('UPDATE entries SET accessed=? WHERE provider=? AND digest=?',(n,key.provider,key.digest))
            return CacheHit(value,created,expires)

    def invalidate(self, key: CacheKey):
        if not isinstance(key, CacheKey): raise CacheError('Invalid key')
        with self._tx() as db:
            return bool(db.execute('DELETE FROM entries WHERE provider=? AND digest=?',(key.provider,key.digest)).rowcount)

    def clear(self, provider=None):
        with self._tx() as db:
            if provider is None: return db.execute('DELETE FROM entries').rowcount
            return db.execute('DELETE FROM entries WHERE provider=?',(_name(provider),)).rowcount

    def status(self):
        with self._tx() as db:
            self._prune(db,self._now(db))
            count,size=db.execute('SELECT count(*),coalesce(sum(length(payload)),0) FROM entries').fetchone()
            return {'entries':count,'payload_bytes':size,'max_entries':self.max_entries,'max_bytes':self.max_bytes}
