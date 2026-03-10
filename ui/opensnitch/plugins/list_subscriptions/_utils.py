import errno
import json
import os
import re
import time
from enum import IntEnum
from datetime import datetime
from typing import Any
from urllib.parse import urlparse, unquote

from opensnitch.utils.xdg import xdg_config_home


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


class RuntimeEvent(IntEnum):
    RUNTIME_ENABLED = 1
    CONFIG_RELOADED = 2
    RUNTIME_DISABLED = 3
    RUNTIME_STOPPED = 4
    RUNTIME_ERROR = 5


def now_iso():
    return datetime.now().astimezone().isoformat()


def parse_iso(ts: str):
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def normalize_iso_timestamp(value: Any, fallback: str | None = None):
    text = str(value or "").strip()
    if text != "" and parse_iso(text) is not None:
        return text
    if fallback:
        return fallback
    return now_iso()


def opt_int(value: Any):
    try:
        return int(value) if value is not None else None
    except Exception:
        return None


def opt_str(value: Any):
    try:
        if value is None:
            return None
        normalized = (str(value) or "").strip().lower()
        return normalized if normalized != "" else None
    except Exception:
        return None


def normalize_lists_dir(path: str | None) -> str:
    default_dir = os.path.join(xdg_config_home, "opensnitch", "list_subscriptions")
    raw = (path or "").strip()
    if raw == "":
        raw = default_dir
    expanded = os.path.expandvars(os.path.expanduser(raw))
    if not os.path.isabs(expanded):
        return os.path.abspath(expanded)
    return expanded


def safe_filename(value: Any) -> str:
    return os.path.basename((str(value or "")).strip())


def filename_from_url(url: str | None) -> str:
    try:
        parsed = urlparse((url or "").strip())
        return safe_filename(unquote(parsed.path or ""))
    except Exception:
        return ""


def slugify_name(name: str | None) -> str:
    raw = (name or "").strip().lower()
    if raw == "":
        return "subscription.list"
    slug = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-._")
    if slug == "":
        slug = "subscription"
    if "." not in slug:
        slug += ".list"
    return safe_filename(slug)


def derive_filename(name: str | None, url: str | None, filename: str | None) -> str:
    fn = safe_filename(filename)
    if fn != "":
        return fn
    fn = filename_from_url(url)
    if fn != "":
        return fn
    return slugify_name(name)


def ensure_filename_type_suffix(filename: str, list_type: str) -> str:
    fn = safe_filename(filename)
    base, ext = os.path.splitext(fn)
    ltype = (list_type or "hosts").strip().lower()
    suffix = f"-{ltype}"
    if not base.lower().endswith(suffix):
        base = f"{base}{suffix}" if base else ltype
    if ext == "":
        ext = ".txt"
    return safe_filename(f"{base}{ext}")


def normalize_group(group: str | None) -> str:
    raw = (group or "").strip().lower()
    if raw == "":
        return ""
    raw = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-._")
    return raw


def normalize_groups(groups: Any) -> list[str]:
    out: list[str] = []
    if isinstance(groups, (list, tuple, set)):
        raw_items = [str(x) for x in groups]
    else:
        raw_items = str(groups or "").split(",")
    seen: set[str] = set()
    for item in raw_items:
        g = normalize_group(item)
        if g == "" or g == "all" or g in seen:
            continue
        seen.add(g)
        out.append(g)
    return out


def dedupe_subscription_identity(
    filename: str,
    name: str,
    url: str,
    list_type: str,
    seen_filenames: dict[str, str] | None,
):
    if seen_filenames is None:
        return filename, name, False

    key = filename
    seen_url = seen_filenames.get(key)
    if seen_url is None:
        seen_filenames[key] = url
        return filename, name, False
    if seen_url == url:
        return filename, name, True

    base, ext = os.path.splitext(filename)
    if ext == "":
        ext = ".txt"
    suffix = f"-{(list_type or 'hosts').strip().lower()}"
    root = base
    if root.lower().endswith(suffix):
        root = root[: -len(suffix)]
    root = root.rstrip("-")
    n = 2
    candidate = filename
    while candidate in seen_filenames:
        candidate = f"{root}-{n}{suffix}{ext}"
        n += 1
    display_name = (name or "").strip()
    if display_name == "":
        display_name = root or "subscription"
    seen_filenames[candidate] = url
    return candidate, f"{display_name} ({n - 1})", False


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


def json_lock_path(path: str) -> str:
    return f"{path}.lock"


def read_json_locked(path: str, timeout: float = 5.0, poll_interval: float = 0.05):
    lock_path = json_lock_path(path)
    lock = FileLock(lock_path)
    deadline = time.monotonic() + max(timeout, 0.0)
    while os.path.exists(lock_path):
        lock.break_stale()
        if not os.path.exists(lock_path):
            break
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for lock: {lock_path}")
        time.sleep(poll_interval)
    return read_json(path)


def write_json_atomic_locked(
    path: str,
    obj: dict[str, Any],
    timeout: float = 5.0,
    poll_interval: float = 0.05,
):
    lock = FileLock(json_lock_path(path))
    deadline = time.monotonic() + max(timeout, 0.0)
    while not lock.acquire():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for lock: {lock.lock_path}")
        time.sleep(poll_interval)
    try:
        write_json_atomic(path, obj)
    finally:
        lock.release()


class FileLock:
    def __init__(self, lock_path: str):
        self.lock_path = lock_path
        self.fd: int | None = None

    def _read_owner_pid(self):
        try:
            with open(self.lock_path, "r", encoding="utf-8") as f:
                raw = f.read().strip()
        except FileNotFoundError:
            return None
        except Exception:
            return -1

        if raw == "":
            return -1
        try:
            return int(raw)
        except Exception:
            return -1

    def _pid_is_alive(self, pid: int):
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except Exception:
            return True
        return True

    def is_stale(self, max_age: float = 30.0):
        try:
            stat = os.stat(self.lock_path)
        except FileNotFoundError:
            return False

        pid = self._read_owner_pid()
        if pid is None:
            return False
        if pid > 0:
            return not self._pid_is_alive(pid)

        age = time.time() - stat.st_mtime
        return age >= max(max_age, 0.0)

    def break_stale(self, max_age: float = 30.0):
        if not self.is_stale(max_age=max_age):
            return False
        try:
            os.unlink(self.lock_path)
            return True
        except FileNotFoundError:
            return True
        except Exception:
            return False

    def acquire(self):
        try:
            self.fd = os.open(
                self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
            )
            os.write(self.fd, str(os.getpid()).encode("utf-8"))
            return True
        except OSError as e:
            if e.errno == errno.EEXIST:
                if self.break_stale():
                    return self.acquire()
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
