import os
import logging
import json
import errno
import hashlib
import threading
import re
from dataclasses import dataclass, field, asdict
from typing import Any
from datetime import datetime, timedelta
from queue import Queue

import requests

from opensnitch.dialogs.stats import StatsDialog
from opensnitch.notifications import DesktopNotifications
from opensnitch.plugins import PluginBase, PluginSignal
from opensnitch.utils import GenericTimer
from opensnitch.utils.xdg import xdg_config_home

ch = logging.StreamHandler()
#ch.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(name)s - [%(levelname)s] %(message)s')
ch.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(ch)
logger.setLevel(logging.WARNING)

# -------------------- constants --------------------

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0 Safari/537.36"
)

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


# -------------------- time helpers (ISO 8601) --------------------

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


# -------------------- JSON IO --------------------

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


# -------------------- lock + atomic swap --------------------

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
    def from_dict(d: dict[str, Any], lists_dir: str | None = None):
        # lists_dir: prefer config value, fallback to lists_dir arg
        lists_dir = str(d.get("lists_dir") or lists_dir or os.path.join(xdg_config_home, "opensnitch", "blocklists", "hosts"))

        def _int(v: int | float | str | None, default: int):
            try:
                return int(v) if v is not None else default
            except Exception:
                return default

        def _str(v: str | None, default: str):
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
    interval: int = 24
    interval_units: str = "hours"
    timeout: int = 60
    timeout_units: str = "seconds"
    max_size: int = 20
    max_size_units: str = "MB"
    interval_seconds: int = 24 * 3600
    timeout_seconds: int = 60
    max_bytes: int = 20 * 1024 * 1024

    @staticmethod
    def from_dict(d: dict[str, Any], defaults: GlobalDefaults):
        if not isinstance(d, dict):
            return None

        name = (d.get("name") or "").strip()
        url = (d.get("url") or "").strip()
        filename = (d.get("filename") or "").strip()
        if not url or not filename:
            return None
        if not name:
            name = filename

        def _opt_int(x: Any):
            try:
                return int(x) if x is not None else None
            except Exception:
                return None

        def _opt_str(x: Any):
            try:
                if x is None:
                    return None
                x = (str(x) or "").strip().lower()
                return x if x != "" else None
            except Exception:
                return None

        interval_raw: Any = d.get("interval")
        timeout_raw: Any = d.get("timeout")
        interval_units_raw: Any = d.get("interval_units")
        timeout_units_raw: Any = d.get("timeout_units")

        interval = _opt_int(interval_raw) or defaults.interval
        interval_units_opt = _opt_str(interval_units_raw)
        interval_units = interval_units_opt or defaults.interval_units
        timeout = _opt_int(timeout_raw) or defaults.timeout
        timeout_units_opt = _opt_str(timeout_units_raw)
        timeout_units = timeout_units_opt or defaults.timeout_units
        max_size = _opt_int(d.get("max_size")) or defaults.max_size
        max_size_units = _opt_str(d.get("max_size_units")) or defaults.max_size_units

        default_interval_seconds = to_seconds(defaults.interval, defaults.interval_units, 24 * 3600)
        default_timeout_seconds = to_seconds(defaults.timeout, defaults.timeout_units, 60)
        default_max_bytes = to_max_bytes(defaults.max_size, defaults.max_size_units, 20 * 1024 * 1024)

        interval_seconds: int | None = None
        interval_is_composite = False
        if interval_units_opt is None:
            interval_seconds = parse_compact_duration(interval_raw)
            interval_is_composite = interval_seconds is not None
        if interval_seconds is None:
            interval_seconds = to_seconds(interval, interval_units, default_interval_seconds)
        elif interval_is_composite:
            interval = interval_seconds
            interval_units = "composite"

        timeout_seconds: int | None = None
        timeout_is_composite = False
        if timeout_units_opt is None:
            timeout_seconds = parse_compact_duration(timeout_raw)
            timeout_is_composite = timeout_seconds is not None
        if timeout_seconds is None:
            timeout_seconds = to_seconds(timeout, timeout_units, default_timeout_seconds)
        elif timeout_is_composite:
            timeout = timeout_seconds
            timeout_units = "composite"

        max_bytes = to_max_bytes(max_size, max_size_units, default_max_bytes)

        return SubscriptionSpec(
            name=name,
            url=url,
            filename=filename,
            enabled=bool(d.get("enabled", True)),
            format=str(d.get("format", "hosts") or "hosts"),

            interval=interval,
            interval_units=interval_units,
            timeout=timeout,
            timeout_units=timeout_units,
            max_size=max_size,
            max_size_units=max_size_units,
            interval_seconds=interval_seconds,
            timeout_seconds=timeout_seconds,
            max_bytes=max_bytes,
        )


@dataclass(frozen=True)
class PluginConfig:
    defaults: GlobalDefaults = field(default_factory=lambda: GlobalDefaults.from_dict({}))
    subscriptions: list[SubscriptionSpec] = field(default_factory=list)

    @staticmethod
    def from_dict(raw_cfg: dict[str, Any], lists_dir: str | None = None):
        raw_cfg = raw_cfg or {}
        if not isinstance(raw_cfg, dict):
            raw_cfg = {}
        defaults = GlobalDefaults.from_dict(raw_cfg, lists_dir)

        subs: list[SubscriptionSpec] = []
        for item in (raw_cfg.get("subscriptions") or []):
            sub = SubscriptionSpec.from_dict(item, defaults)
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
    def from_dict(d: dict[str, Any]):
        m = ListMetadata()
        if not isinstance(d, dict):
            return m

        def _int(v: Any, default: int):
            try:
                return int(v) if v is not None else default
            except Exception:
                return default

        def _str(v: Any, default: str = ""):
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

    def to_dict(self):
        return asdict(self)


# -------------------- plugin core --------------------

class ListSubscriptions(PluginBase):
    """ A plugin to manage list subscriptions (e.g. blocklists).

    The plugin is configured via a JSON file specifying a list of subscriptions.
    Each subscription has a URL and a local filename to save to.
    The plugin periodically checks each URL for updates, using HTTP cache validators to avoid unnecessary downloads.
    Metadata about each subscription is stored in a sidecar JSON file (same name + .meta.json) to track last update time, errors, backoff, etc.
    The plugin exposes a results queue for the UI to display subscription status and errors.
    """
    # fields overriden from parent class
    name = "List Subscriptions"
    version = 0
    author = "opensnitch"
    created = ""
    modified = ""
    enabled = False
    description = "Manage list subscriptions (e.g. blocklists) with periodic updates"

    # default
    TYPE = [PluginBase.TYPE_GLOBAL]

    # runtime state
    scheduled_tasks: dict[str, GenericTimer] = {}
    default_conf = "{0}/{1}".format(xdg_config_home, "opensnitch/actions/list_subscriptions.json")
    default_lists_dir = os.path.join(xdg_config_home, "opensnitch", "blocklists", "hosts")

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self._log = logger
        self.signal_in.connect(self.cb_signal)
        self._desktop_notifications = DesktopNotifications()
        self._ok_msg = ""
        self._err_msg = ""
        self._notify: dict[str, Any] | None = None
        self._notify_title = "[OpenSnitch] List subscriptions downloader"
        self._resultsQueue: Queue[tuple[str, bool, str]] = Queue()
        self._running = False
        self._app_icon = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../../res/icon-white.svg")

        if config.get("enabled") is True:
            self.enabled = True

        # Load config
        plugin_cfg: Any = config.get("config", {})
        if not isinstance(plugin_cfg, dict):
            plugin_cfg = {}
        self._config = PluginConfig.from_dict(plugin_cfg, lists_dir=self.default_lists_dir)
        self._notify = plugin_cfg.get("notify")
        if isinstance(self._notify, dict):
            ok = self._notify.get("success")
            err = self._notify.get("error")
            if isinstance(ok, dict):
                ok_msg = ok.get("desktop")
                if ok_msg:
                    self._ok_msg = ok_msg
            if isinstance(err, dict):
                err_msg = err.get("desktop")
                if err_msg:
                    self._err_msg = err_msg
        else:
            self._notify = None

        # Set up requests session with default UA
        self._session: requests.Session = requests.Session()
        if self._config.defaults.user_agent:
            self._session.headers.update({"User-Agent": self._config.defaults.user_agent})
        else:
            self._session.headers.update({"User-Agent": DEFAULT_UA})

    # -------- metadata sidecar --------

    def _paths(self, sub: SubscriptionSpec):
        if self._config is None:
            raise RuntimeError("PluginConfig is not loaded")
        list_path = os.path.join(self._config.defaults.lists_dir, sub.filename)
        meta_path = list_path + ".meta.json"
        return list_path, meta_path

    def _load_meta(self, meta_path: str):
        try:
            return ListMetadata.from_dict(read_json(meta_path))
        except Exception:
            return ListMetadata()

    def _save_meta(self, meta_path: str, meta: ListMetadata):
        write_json_atomic(meta_path, meta.to_dict())

    # -------- timer lifecycle --------

    def _sub_key(self, sub: SubscriptionSpec):
        base = f"{sub.url}|{sub.filename}"
        return hashlib.sha1(base.encode("utf-8")).hexdigest()[:16]

    def configure(self, parent: Any = None):
        if type(parent) == StatsDialog:
            pass
            #_gui.add_panel_section()

    def compile(self):
        """
        Build one GenericTimer per subscription.
        Stops timers removed from config.
        """
        if not self._config:
            return

        latest_keys: set[str] = set()

        for sub in self._config.subscriptions:
            if not sub.enabled:
                continue

            key = self._sub_key(sub)
            latest_keys.add(key)

            if self._config is None:
                continue
            interval_s = sub.interval_seconds

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

    def run(self, parent: Any = None, args: tuple[Any, ...] = ()):  # type: ignore[override]
        """
        Start timers.
        """

        if parent == StatsDialog:
            pass

        self._running = True

        for t in self.scheduled_tasks.values():
            try:
                t.start()
            except Exception:
                pass

    def stop(self):
        """
        Stop timers.
        """
        for t in self.scheduled_tasks.values():
            try:
                t.stop()
            except Exception:
                pass
        self.scheduled_tasks.clear()
        self._running = False

    # -------- scheduled execution --------

    def cb_run_tasks(self, args: tuple[str, SubscriptionSpec]):
        """
        Timer callback for one subscription.
        Mirrors downloader behavior: start worker thread, join it,
        then immediately evaluate queued result.
        """
        key: str
        sub: SubscriptionSpec
        key, sub = args

        # due/backoff gate via sidecar meta
        _, meta_path = self._paths(sub)
        meta = self._load_meta(meta_path)

        if self._in_backoff(meta):
            return
        if not self._is_due(meta, sub):
            return

        th = threading.Thread(target=self.download, args=(key, sub))
        th.start()
        th.join()

        matched: list[tuple[str, bool, str]] = []
        unmatched: list[tuple[str, bool, str]] = []
        while not self._resultsQueue.empty():
            item = self._resultsQueue.get_nowait()
            if len(item) >= 3 and item[0] == key:
                matched.append(item)
            else:
                unmatched.append(item)
        for item in unmatched:
            self._resultsQueue.put(item)

        if not matched:
            logger.debug("cb_run_tasks() no result for key=%s sub=%s", key, sub.name)
            return

        updated: bool = False
        statuses: list[str] = []
        for _, ok, status in matched:
            updated = ok
            statuses.append(status)
        if updated:
            result_msg = self._ok_msg or f"{sub.name}: {', '.join(statuses)}"
        else:
            result_msg = self._err_msg or f"{sub.name} failed: {', '.join(statuses)}"

        if self._notify is not None and self._desktop_notifications.is_available() and self._desktop_notifications.are_enabled():
            self._desktop_notifications.show(self._notify_title, result_msg, self._app_icon)

    def cb_signal(self, signal: Any):
        logger.debug("cb_signal: %s, %s", self.name, signal)
        try:
            if signal == PluginSignal.ENABLE:
                self.enabled = True

            if signal['signal'] == PluginSignal.DISABLE or signal['signal'] == PluginSignal.STOP: #type: ignore[union-attr]
                for t in self.scheduled_tasks:
                    logger.debug("cb_signal.stopping task: %s, %s", self.name, signal)
                    self.scheduled_tasks[t].stop()

        except Exception as e:
            logger.warning("cb_signal() exception: %s", repr(e))

    def _in_backoff(self, meta: ListMetadata):
        if not meta.backoff_until:
            return False
        dt = parse_iso(meta.backoff_until)
        if not dt:
            return False
        return datetime.now().astimezone() < dt

    def _is_due(self, meta: ListMetadata, sub: SubscriptionSpec):
        if not meta.last_checked:
            return True
        lc = parse_iso(meta.last_checked)
        if not lc:
            return True
        return (datetime.now().astimezone() - lc).total_seconds() >= sub.interval_seconds

    # -------- worker: download + update metadata --------

    def _mark_failure(self, meta: ListMetadata, err: str):
        meta.fail_count = int(meta.fail_count or 0) + 1
        meta.last_error = err
        meta.last_result = "error"

        seconds = min((2 ** max(0, meta.fail_count)) * 60, 6 * 3600)
        meta.backoff_until = (datetime.now().astimezone() + timedelta(seconds=seconds)).isoformat()

    def download(self, key: str, sub: SubscriptionSpec):
        list_path, meta_path = self._paths(sub)
        os.makedirs(os.path.dirname(list_path), exist_ok=True)

        meta = self._load_meta(meta_path)

        # keep meta aligned
        meta.version = 1
        meta.url = sub.url
        meta.format = sub.format

        meta.last_checked = now_iso()
        meta.last_error = ""

        # conditional headers
        headers: dict[str, str] = {}
        if meta.etag:
            headers["If-None-Match"] = meta.etag
        if meta.last_modified:
            headers["If-Modified-Since"] = meta.last_modified

        headers["User-Agent"] = self._config.defaults.user_agent or DEFAULT_UA

        lock = FileLock(list_path + ".lock")
        if not lock.acquire():
            meta.last_result = "busy"
            self._save_meta(meta_path, meta)
            self._resultsQueue.put((key, False, "busy"))
            return False

        try:
            # requests defaults except UA; timeout is used
            try:
                r: requests.Response = self._session.get(
                    sub.url, headers=headers, timeout=sub.timeout_seconds, stream=True
                )
            except Exception as e:
                self._mark_failure(meta, repr(e))
                self._save_meta(meta_path, meta)
                self._resultsQueue.put((key, False, "request_error"))
                return False

            try:
                if r.status_code == 304:
                    meta.fail_count = 0
                    meta.backoff_until = ""
                    meta.last_result = "not_modified"
                    self._save_meta(meta_path, meta)
                    self._resultsQueue.put((key, True, "not_modified"))
                    return True

                if r.status_code != 200:
                    self._mark_failure(meta, f"http_{r.status_code}")
                    self._save_meta(meta_path, meta)
                    self._resultsQueue.put((key, False, f"http_{r.status_code}"))
                    return False

                cl: str | None = r.headers.get("Content-Length")
                if cl:
                    try:
                        if int(cl) > sub.max_bytes:
                            self._mark_failure(meta, f"too_large:{cl}")
                            self._save_meta(meta_path, meta)
                            self._resultsQueue.put((key, False, "too_large"))
                            return False
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
                            if downloaded > sub.max_bytes:
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

                    if sub.format.lower() == "hosts" and not is_hosts_file_like(sample_lines):
                        try:
                            os.remove(tmp)
                        except Exception:
                            pass
                        self._mark_failure(meta, "bad_format_hosts")
                        self._save_meta(meta_path, meta)
                        self._resultsQueue.put((key, False, "bad_format"))
                        return False

                    os.replace(tmp, list_path)

                except Exception as e:
                    try:
                        if os.path.exists(tmp):
                            os.remove(tmp)
                    except Exception:
                        pass
                    self._mark_failure(meta, repr(e))
                    self._save_meta(meta_path, meta)
                    self._resultsQueue.put((key, False, "write_error"))
                    return False

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
                self._resultsQueue.put((key, True, "updated"))
                return True
            finally:
                r.close()
        except Exception as e:
            self._mark_failure(meta, repr(e))
            self._save_meta(meta_path, meta)
            self._resultsQueue.put((key, False, "unexpected_error"))
            return False

        finally:
            lock.release()
