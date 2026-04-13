import json
import os
import time
from typing import Any

from opensnitch.plugins.list_subscriptions.io.lock import FileLock


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


def json_lock_path(path: str):
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
