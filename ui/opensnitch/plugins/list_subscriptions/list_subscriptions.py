import os
import json
import errno
import hashlib
import threading
from dataclasses import dataclass, field, asdict
from typing import Any
from datetime import datetime, timedelta
import time
from queue import Queue

import requests

from opensnitch.utils import GenericTimer
from opensnitch.utils.duration import duration
from opensnitch.utils.logger import logger
from opensnitch.utils.xdg import xdg_config_home


# -------------------- constants --------------------

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0 Safari/537.36"
)

UNIT_TO_DUR = {
    "seconds": "s",
    "minutes": "m",
    "hours": "h",
    "days": "d",
    "weeks": "w",
}

SIZE_MULT = {
    "bytes": 1,
    "kb": 1024,
    "mb": 1024 * 1024,
    "gb": 1024 * 1024 * 1024,
}


# -------------------- time helpers (ISO 8601) --------------------

def now_iso() -> str:
    return datetime.now().astimezone().isoformat()


def parse_iso(ts: str):
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def to_seconds(value, units, default_seconds: int) -> int:
    try:
        if value is None:
            return default_seconds
        u = (units or "seconds").lower()
        suf = UNIT_TO_DUR.get(u, "s")
        sec = duration.to_seconds(f"{int(value)}{suf}")
        return sec if sec > 0 else default_seconds
    except Exception:
        return default_seconds


def to_max_bytes(value, units, default_bytes: int) -> int:
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


# -------------------- JSON IO --------------------

def read_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json_atomic(path: str, obj: dict):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# -------------------- lock + atomic swap --------------------

class FileLock:
    def __init__(self, lock_path: str):
        self.lock_path = lock_path
        self.fd = None

    def acquire(self) -> bool:
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


def looks_like_hosts_file(sample_lines: list[str]) -> bool:
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


# -------------------- dataclasses: schema --------------------

@dataclass(frozen=True)
class GlobalDefaults:
    lists_dir: str
    interval: int = 24
    interval_units: str = "hours"
    timeout: int = 60
    timeout_units: str = "seconds"
    max_size: int = 20
    max_size_units: str = "MB"
    user_agent: str | None = DEFAULT_UA

    @staticmethod
    def from_dict(d: dict[str, Any], computed_lists_dir: str) -> "GlobalDefaults":
        # lists_dir: prefer config value, fallback to computed
        lists_dir = str(d.get("lists_dir") or computed_lists_dir)

        def _int(v: int | float | str | None, default: int) -> int:
            try:
                return int(v) if v is not None else default
            except Exception:
                return default

        def _str(v: str | None, default: str) -> str:
            v = (v or "").strip()
            return v if v else default

        return GlobalDefaults(
            lists_dir=lists_dir,
            interval=_int(d.get("interval"), 24),
            interval_units=_str(d.get("interval_units"), "hours"),
            timeout=_int(d.get("timeout"), 60),
            timeout_units=_str(d.get("timeout_units"), "seconds"),
            max_size=_int(d.get("max_size"), 20),
            max_size_units=_str(d.get("max_size_units"), "MB"),
            user_agent=(d.get("user_agent") or DEFAULT_UA),
        )


@dataclass(frozen=True)
class SubscriptionSpec:
    name: str
    url: str
    filename: str
    enabled: bool = True
    format: str = "hosts"

    # optional overrides
    interval: int | None = None
    interval_units: str | None = None
    timeout: int | None = None
    timeout_units: str | None = None
    max_size: int | None = None
    max_size_units: str | None = None
    user_agent: str | None = None

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "SubscriptionSpec | None":
        if not isinstance(d, dict):
            return None

        name = (d.get("name") or "").strip()
        url = (d.get("url") or "").strip()
        filename = (d.get("filename") or "").strip()
        if not url or not filename:
            return None
        if not name:
            name = filename

        def _opt_int(x):
            try:
                return int(x) if x is not None else None
            except Exception:
                return None

        def _opt_str(x):
            x = (x or "").strip()
            return x or None

        return SubscriptionSpec(
            name=name,
            url=url,
            filename=filename,
            enabled=bool(d.get("enabled", True)),
            format=str(d.get("format", "hosts") or "hosts"),

            interval=_opt_int(d.get("interval")),
            interval_units=_opt_str(d.get("interval_units")),
            timeout=_opt_int(d.get("timeout")),
            timeout_units=_opt_str(d.get("timeout_units")),
            max_size=_opt_int(d.get("max_size")),
            max_size_units=_opt_str(d.get("max_size_units")),
            user_agent=_opt_str(d.get("user_agent")),
        )


@dataclass(frozen=True)
class PluginConfig:
    defaults: GlobalDefaults
    subscriptions: list[SubscriptionSpec] = field(default_factory=list)

    @staticmethod
    def from_actions_config(raw_cfg: dict[str, Any], computed_lists_dir: str) -> "PluginConfig":
        raw_cfg = raw_cfg or {}
        defaults = GlobalDefaults.from_dict(raw_cfg, computed_lists_dir)

        subs: list[SubscriptionSpec] = []
        for item in (raw_cfg.get("subscriptions") or []):
            sub = SubscriptionSpec.from_dict(item)
            if sub is not None:
                subs.append(sub)

        return PluginConfig(defaults=defaults, subscriptions=subs)


@dataclass
class ListMetadata:
    version: int = 1
    url: str = ""
    format: str = "hosts"

    etag: str = ""
    last_modified: str = ""  # HTTP header value, not ISO

    last_checked: str = ""   # ISO
    last_updated: str = ""   # ISO
    backoff_until: str = ""  # ISO

    last_result: str = "never"
    last_error: str = ""

    fail_count: int = 0
    bytes: int = 0

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "ListMetadata":
        m = ListMetadata()
        if not isinstance(d, dict):
            return m

        def _int(v, default):
            try:
                return int(v) if v is not None else default
            except Exception:
                return default

        def _str(v, default=""):
            return str(v or default)

        m.version = _int(d.get("version", 1), 1)
        m.url = _str(d.get("url", ""))
        m.format = _str(d.get("format", "hosts")) or "hosts"

        m.etag = _str(d.get("etag", ""))
        m.last_modified = _str(d.get("last_modified", ""))

        m.last_checked = _str(d.get("last_checked", ""))
        m.last_updated = _str(d.get("last_updated", ""))
        m.backoff_until = _str(d.get("backoff_until", ""))

        m.last_result = _str(d.get("last_result", "never")) or "never"
        m.last_error = _str(d.get("last_error", ""))

        m.fail_count = _int(d.get("fail_count", 0), 0)
        m.bytes = _int(d.get("bytes", 0), 0)

        return m

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# -------------------- config resolution --------------------

def effective_user_agent(sub: SubscriptionSpec, defaults: GlobalDefaults) -> str:
    return sub.user_agent or defaults.user_agent or DEFAULT_UA

def effective_interval_seconds(sub: SubscriptionSpec, defaults: GlobalDefaults) -> int:
    v = sub.interval if sub.interval is not None else defaults.interval
    u = sub.interval_units or defaults.interval_units
    return to_seconds(v, u, default_seconds=24 * 3600)

def effective_timeout_seconds(sub: SubscriptionSpec, defaults: GlobalDefaults) -> int:
    v = sub.timeout if sub.timeout is not None else defaults.timeout
    u = sub.timeout_units or defaults.timeout_units
    return to_seconds(v, u, default_seconds=60)

def effective_max_bytes(sub: SubscriptionSpec, defaults: GlobalDefaults) -> int:
    v = sub.max_size if sub.max_size is not None else defaults.max_size
    u = sub.max_size_units or defaults.max_size_units
    # default 20MB
    return to_max_bytes(v, u, default_bytes=20 * 1024 * 1024)


# -------------------- inotify watcher --------------------

class ConfigWatcher(threading.Thread):
    """
    Watches a single config file via inotify and calls callback() on changes.
    Uses a debounce window to avoid duplicate reloads on atomic-save patterns.
    """
    def __init__(self, config_path: str, callback, debounce_ms: int = 250):
        try:
            from inotify_simple import INotify, flags
        except ImportError:
            raise RuntimeError("inotify_simple is required for ConfigWatcher")
        super().__init__(daemon=True)
        self.config_path = config_path
        self.callback = callback
        self.debounce_ms = debounce_ms
        self._stop = threading.Event()

        self._dir = os.path.dirname(config_path)
        self._base = os.path.basename(config_path)

    def stop(self):
        self._stop.set()

    def run(self):
        try:
            ino = INotify()
            wd = ino.add_watch(
                self._dir,
                flags.CLOSE_WRITE | flags.MOVED_TO | flags.CREATE | flags.DELETE | flags.MODIFY
            )

            last_fire = 0.0

            while not self._stop.is_set():
                events = ino.read(timeout=int(self.debounce_ms))
                if not events:
                    continue

                # If any relevant event touches our file, debounce+fire
                touched = False
                for e in events:
                    name = e.name or ""
                    if name == self._base:
                        touched = True
                        break

                if not touched:
                    continue

                now = time.time()
                if (now - last_fire) * 1000.0 < self.debounce_ms:
                    continue
                last_fire = now

                try:
                    self.callback()
                except Exception:
                    # callback must not kill watcher
                    pass

        except Exception:
            # if inotify fails, we silently do nothing (or log if desired)
            return


# -------------------- plugin core --------------------

class ListSubscriptions:
    """
    - Single main config file (array of subscriptions).
    - Sidecar metadata per list file.
    - Per-subscription timers.
    - inotify reload of main config on changes.
    """

    def __init__(self, config_path: str | None = None):
        logger.new("list_subscriptions")
        self._log = logger.get("list_subscriptions")

        # Where the actions JSON lives (example default)
        self.config_path = config_path or os.path.join(
            xdg_config_home, "opensnitch", "actions", "listSubscriptionsActions.json"
        )

        # Typed config
        self.cfg_typed: PluginConfig | None = None

        # Runtime
        self._resultsQueue = Queue()
        self.scheduled_tasks: dict[str, GenericTimer] = {}  # key -> timer
        self._threads: dict[str, threading.Thread] = {}     # key -> thread
        self._watcher: ConfigWatcher | None = None

        # requests defaults except UA
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": DEFAULT_UA})

        # initial load
        self.reload_config()

    # -------- config + reload --------

    def reload_config(self):
        """
        Reload main json config file, rebuild timers.
        """
        computed_lists_dir = os.path.join(xdg_config_home, "opensnitch", "blocklists", "hosts")

        try:
            raw = read_json(self.config_path)
            # navigate to actions.list_subscriptions.config
            cfg = (
                raw.get("actions", {})
                   .get("list_subscriptions", {})
                   .get("config", {})
            )
            self.cfg_typed = PluginConfig.from_actions_config(cfg, computed_lists_dir)
        except Exception as e:
            self._log.warning("Failed to load config %s: %s", self.config_path, repr(e))
            # Keep last good cfg_typed if available
            if self.cfg_typed is None:
                # minimal fallback config so plugin doesn't crash
                defaults = GlobalDefaults.from_dict({"lists_dir": computed_lists_dir}, computed_lists_dir)
                self.cfg_typed = PluginConfig(defaults=defaults, subscriptions=[])
            return

        # update session UA default (sub-level UA will still override per request)
        self._session.headers.update({"User-Agent": self.cfg_typed.defaults.user_agent or DEFAULT_UA})

        # rebuild timers
        self.compile()

    # -------- metadata sidecar --------

    def _paths(self, sub: SubscriptionSpec) -> tuple[str, str]:
        if self.cfg_typed is None:
            raise RuntimeError("PluginConfig is not loaded")
        list_path = os.path.join(self.cfg_typed.defaults.lists_dir, sub.filename)
        meta_path = list_path + ".meta.json"
        return list_path, meta_path

    def _load_meta(self, meta_path: str) -> ListMetadata:
        try:
            return ListMetadata.from_dict(read_json(meta_path))
        except Exception:
            return ListMetadata()

    def _save_meta(self, meta_path: str, meta: ListMetadata):
        write_json_atomic(meta_path, meta.to_dict())

    # -------- timer lifecycle --------

    def _sub_key(self, sub: SubscriptionSpec) -> str:
        base = f"{sub.url}|{sub.filename}"
        return hashlib.sha1(base.encode("utf-8")).hexdigest()[:16]

    def compile(self):
        """
        Build one GenericTimer per subscription.
        Stops timers removed from config.
        """
        if not self.cfg_typed:
            return

        latest_keys = set()

        for sub in self.cfg_typed.subscriptions:
            if not sub.enabled:
                continue

            key = self._sub_key(sub)
            latest_keys.add(key)

            if self.cfg_typed is None:
                continue
            interval_s = effective_interval_seconds(sub, self.cfg_typed.defaults)

            # recreate timer (simple, applies interval changes)
            if key in self.scheduled_tasks:
                try:
                    self.scheduled_tasks[key].stop()
                except Exception:
                    pass

            self.scheduled_tasks[key] = GenericTimer(
                interval_s, True, self.cb_run_tasks, (key, sub)
            )

        # stop removed timers
        for key in list(self.scheduled_tasks.keys()):
            if key not in latest_keys:
                try:
                    self.scheduled_tasks[key].stop()
                except Exception:
                    pass
                self.scheduled_tasks.pop(key, None)
                self._threads.pop(key, None)

    def run(self):
        """
        Start timers + start inotify watcher.
        """
        self.compile()

        for t in self.scheduled_tasks.values():
            try:
                t.start()
            except Exception:
                pass

        # start watcher (reload on config edit)
        if self._watcher is None:
            self._watcher = ConfigWatcher(self.config_path, self.reload_config, debounce_ms=250)
            self._watcher.start()

    def stop(self):
        """
        Stop timers + watcher.
        """
        for t in self.scheduled_tasks.values():
            try:
                t.stop()
            except Exception:
                pass
        self.scheduled_tasks.clear()

        if self._watcher is not None:
            self._watcher.stop()
            self._watcher = None

    # -------- scheduled execution --------

    def cb_run_tasks(self, args):
        """
        Timer callback for ONE subscription; spawns thread for network work.
        """
        key, sub = args

        th = self._threads.get(key)
        if th is not None and th.is_alive():
            return

        # due/backoff gate via sidecar meta
        list_path, meta_path = self._paths(sub)
        meta = self._load_meta(meta_path)

        if self._in_backoff(meta):
            return
        if not self._is_due(meta, sub):
            return

        th = threading.Thread(target=self.download, args=(key, sub), daemon=True)
        th.start()
        self._threads[key] = th

    def _in_backoff(self, meta: ListMetadata) -> bool:
        if not meta.backoff_until:
            return False
        dt = parse_iso(meta.backoff_until)
        if not dt:
            return False
        return datetime.now().astimezone() < dt

    def _is_due(self, meta: ListMetadata, sub: SubscriptionSpec) -> bool:
        if not meta.last_checked:
            return True
        lc = parse_iso(meta.last_checked)
        if not lc:
            return True
        if self.cfg_typed is None:
            # fallback to 24 hours if config is not loaded
            interval_s = 24 * 3600
        else:
            interval_s = effective_interval_seconds(sub, self.cfg_typed.defaults)
        return (datetime.now().astimezone() - lc).total_seconds() >= interval_s

    # -------- worker: download + update metadata --------

    def _mark_failure(self, meta: ListMetadata, err: str):
        meta.fail_count = int(meta.fail_count or 0) + 1
        meta.last_error = err
        meta.last_result = "error"

        seconds = min((2 ** max(0, meta.fail_count)) * 60, 6 * 3600)
        meta.backoff_until = (datetime.now().astimezone() + timedelta(seconds=seconds)).isoformat()

    def download(self, key: str, sub: SubscriptionSpec):
        ok, status = self._download_one(sub)
        self._resultsQueue.put((key, ok, status))

    def _download_one(self, sub: SubscriptionSpec) -> tuple[bool, str]:
        list_path, meta_path = self._paths(sub)
        os.makedirs(os.path.dirname(list_path), exist_ok=True)

        meta = self._load_meta(meta_path)

        # keep meta aligned
        meta.version = 1
        meta.url = sub.url
        meta.format = sub.format

        meta.last_checked = now_iso()
        meta.last_error = ""

        timeout_s = effective_timeout_seconds(sub, self.cfg_typed.defaults)
        max_bytes = effective_max_bytes(sub, self.cfg_typed.defaults)

        # conditional headers
        headers = {}
        if meta.etag:
            headers["If-None-Match"] = meta.etag
        if meta.last_modified:
            headers["If-Modified-Since"] = meta.last_modified

        headers["User-Agent"] = effective_user_agent(sub, self.cfg_typed.defaults)

        lock = FileLock(list_path + ".lock")
        if not lock.acquire():
            meta.last_result = "busy"
            self._save_meta(meta_path, meta)
            return True, "busy"

        try:
            # requests defaults except UA; timeout is used
            try:
                r = self._session.get(sub.url, headers=headers, timeout=timeout_s, stream=True)
            except Exception as e:
                self._mark_failure(meta, repr(e))
                self._save_meta(meta_path, meta)
                return False, "request_error"

            if r.status_code == 304:
                meta.fail_count = 0
                meta.backoff_until = ""
                meta.last_result = "not_modified"
                self._save_meta(meta_path, meta)
                return True, "not_modified"

            if r.status_code != 200:
                self._mark_failure(meta, f"http_{r.status_code}")
                self._save_meta(meta_path, meta)
                return False, f"http_{r.status_code}"

            cl = r.headers.get("Content-Length")
            if cl:
                try:
                    if int(cl) > max_bytes:
                        self._mark_failure(meta, f"too_large:{cl}")
                        self._save_meta(meta_path, meta)
                        return False, "too_large"
                except Exception:
                    pass

            tmp = list_path + ".tmp"
            downloaded = 0
            sample_lines: list[str] = []

            try:
                with open(tmp, "wb") as f:
                    for chunk in r.iter_content(chunk_size=32 * 1024):
                        if not chunk:
                            continue
                        downloaded += len(chunk)
                        if downloaded > max_bytes:
                            raise RuntimeError("too_large_streamed")
                        f.write(chunk)

                        if sub.format.lower() == "hosts" and len(sample_lines) < 200:
                            txt = chunk.decode("utf-8", errors="ignore")
                            for ln in txt.splitlines():
                                if len(sample_lines) < 200:
                                    sample_lines.append(ln)
                                else:
                                    break

                    f.flush()
                    os.fsync(f.fileno())

                if sub.format.lower() == "hosts" and not looks_like_hosts_file(sample_lines):
                    try:
                        os.remove(tmp)
                    except Exception:
                        pass
                    self._mark_failure(meta, "bad_format_hosts")
                    self._save_meta(meta_path, meta)
                    return False, "bad_format"

                os.replace(tmp, list_path)

            except Exception as e:
                try:
                    if os.path.exists(tmp):
                        os.remove(tmp)
                except Exception:
                    pass
                self._mark_failure(meta, repr(e))
                self._save_meta(meta_path, meta)
                return False, "write_error"

            # update cache validators
            et = r.headers.get("ETag")
            lm = r.headers.get("Last-Modified")
            if et:
                meta.etag = et
            if lm:
                meta.last_modified = lm

            meta.bytes = downloaded
            meta.last_updated = now_iso()
            meta.fail_count = 0
            meta.backoff_until = ""
            meta.last_result = "updated"
            self._save_meta(meta_path, meta)
            return True, "updated"

        finally:
            lock.release()
