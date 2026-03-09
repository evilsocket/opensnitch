import errno
import json
import os
import re
from datetime import datetime
from typing import Any


TIME_MULT = {
    "seconds": 1,
    "minutes": 60,
    "hours": 60 * 60,
    "days": 24 * 60 * 60,
    "weeks": 7 * 24 * 60 * 60,
    "s": 1,
    "m": 60,
    "h": 60 * 60,
    "d": 24 * 60 * 60,
    "w": 7 * 24 * 60 * 60,
}
SHORT_TIME_MULT = {
    "s": TIME_MULT["seconds"],
    "m": TIME_MULT["minutes"],
    "h": TIME_MULT["hours"],
    "d": TIME_MULT["days"],
    "w": TIME_MULT["weeks"],
}

SIZE_MULT = {
    "bytes": 1,
    "kb": 1024,
    "mb": 1024 * 1024,
    "gb": 1024 * 1024 * 1024,
}


def now_iso():
    return datetime.now().astimezone().isoformat()


def parse_iso(ts: str):
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def to_seconds(value: Any, units: str | None, default_seconds: int):
    try:
        if value is None:
            return default_seconds
        u = (units or "seconds").lower()
        mult = TIME_MULT.get(u)
        if mult is None:
            return default_seconds
        sec = int(value) * mult
        return sec if sec > 0 else default_seconds
    except Exception:
        return default_seconds


def parse_compact_duration(value: Any):
    if not isinstance(value, str):
        return None
    s = value.strip().lower().replace(" ", "")
    if not s:
        return None

    total = 0
    pos = 0
    for m in re.finditer(r"(\d+)([smhdw])", s):
        if m.start() != pos:
            return None
        total += int(m.group(1)) * SHORT_TIME_MULT[m.group(2)]
        pos = m.end()
    if pos != len(s):
        return None
    return total if total > 0 else None


def to_max_bytes(value: Any, units: str | None, default_bytes: int):
    try:
        if value is None:
            return default_bytes
        u = (units or "bytes").lower()
        mult = SIZE_MULT.get(u)
        if mult is None:
            return default_bytes
        out = int(value) * mult
        return out if out > 0 else default_bytes
    except Exception:
        return default_bytes


def read_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json_atomic(path: str, obj: dict[str, Any]):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class FileLock:
    def __init__(self, lock_path: str):
        self.lock_path = lock_path
        self.fd: int | None = None

    def acquire(self):
        try:
            self.fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(self.fd, str(os.getpid()).encode("utf-8"))
            return True
        except OSError as e:
            if e.errno == errno.EEXIST:
                return False
            raise

    def release(self):
        try:
            if self.fd is not None:
                os.close(self.fd)
        finally:
            self.fd = None
            try:
                os.unlink(self.lock_path)
            except FileNotFoundError:
                pass


def is_hosts_file_like(sample_lines: list[str]):
    valid = 0
    total = 0
    for line in sample_lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        total += 1
        parts = s.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::"):
            if "." in parts[1] and "/" not in parts[1]:
                valid += 1
        elif len(parts) == 1 and "." in parts[0]:
            valid += 1
    if total <= 10:
        return True
    return (valid / max(total, 1)) >= 0.60
