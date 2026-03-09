import os
import logging
import hashlib
import threading
import shutil
import sys
from typing import Any
from datetime import datetime, timedelta
from queue import Queue

import requests
if "PyQt5" in sys.modules:
    from PyQt5 import QtCore, QtGui
elif "PyQt6" in sys.modules:
    from PyQt6 import QtCore, QtGui
else:
    try:
        from PyQt6 import QtCore, QtGui
    except Exception:
        from PyQt5 import QtCore, QtGui

from opensnitch.dialogs.stats import StatsDialog
from opensnitch.notifications import DesktopNotifications
from opensnitch.plugins import PluginBase, PluginSignal
from opensnitch.utils import GenericTimer
from opensnitch.utils.xdg import xdg_config_home
from opensnitch.plugins.list_subscriptions._models import (
    DEFAULT_UA,
    ListMetadata,
    PluginConfig,
    SubscriptionSpec,
    ensure_filename_type_suffix,
    normalize_group,
    normalize_lists_dir,
)
from opensnitch.plugins.list_subscriptions._utils import (
    FileLock,
    is_hosts_file_like,
    now_iso,
    parse_iso,
    read_json,
    write_json_atomic,
)

ch = logging.StreamHandler()
#ch.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(name)s - [%(levelname)s] %(message)s')
ch.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(ch)
logger.setLevel(logging.WARNING)


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
    name = "List_subscriptions"
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
    default_lists_dir = os.path.join(xdg_config_home, "opensnitch", "list_subscriptions")

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
        self._cfg_dialog = None
        self._cfg_action = None

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
        lists_dir = normalize_lists_dir(self._config.defaults.lists_dir)
        os.makedirs(lists_dir, mode=0o700, exist_ok=True)
        sources_dir = os.path.join(lists_dir, "sources.list.d")
        os.makedirs(sources_dir, mode=0o700, exist_ok=True)
        safe_filename = os.path.basename((sub.filename or "").strip())
        if safe_filename == "":
            safe_filename = "subscription.list"
        safe_filename = ensure_filename_type_suffix(safe_filename, sub.format)
        base, _ext = os.path.splitext(safe_filename)
        list_type = (sub.format or "hosts").strip().lower()
        suffix = f"-{list_type}"
        sub_dirname = base if base else "subscription"
        if not sub_dirname.lower().endswith(suffix):
            sub_dirname = f"{sub_dirname}{suffix}"
        sub_dir = os.path.join(sources_dir, sub_dirname)
        os.makedirs(sub_dir, mode=0o700, exist_ok=True)
        list_path = os.path.join(sub_dir, safe_filename)
        meta_path = list_path + ".meta.json"
        return list_path, meta_path

    def _rules_root_dir(self):
        if self._config is None:
            return os.path.join(self.default_lists_dir, "rules.list.d")
        return os.path.join(normalize_lists_dir(self._config.defaults.lists_dir), "rules.list.d")

    def _sources_root_dir(self):
        if self._config is None:
            return os.path.join(self.default_lists_dir, "sources.list.d")
        return os.path.join(normalize_lists_dir(self._config.defaults.lists_dir), "sources.list.d")

    def _sync_sources_dirs(self):
        if self._config is None:
            return
        sources_dir = self._sources_root_dir()
        os.makedirs(sources_dir, mode=0o700, exist_ok=True)

        desired_dirs: set[str] = set()
        for sub in self._config.subscriptions:
            list_path, _ = self._paths(sub)
            desired_dirs.add(os.path.dirname(list_path))

        for entry in os.listdir(sources_dir):
            p = os.path.join(sources_dir, entry)
            try:
                if os.path.isdir(p) and not os.path.islink(p):
                    if p not in desired_dirs:
                        shutil.rmtree(p)
                else:
                    os.unlink(p)
            except Exception:
                pass

    def _sync_global_symlinks(self):
        if self._config is None:
            return
        rules_dir = self._rules_root_dir()
        os.makedirs(rules_dir, mode=0o700, exist_ok=True)
        desired: dict[str, dict[str, str]] = {}
        for idx, sub in enumerate(self._config.subscriptions):
            if not getattr(sub, "enabled", True):
                continue
            list_path, _ = self._paths(sub)
            if not os.path.exists(list_path):
                continue
            raw_groups: tuple[str, ...] = getattr(sub, "groups", tuple())
            groups: list[str] = list(raw_groups)
            groups.append("all")
            groups = sorted(normalize_group(g) for g in set(groups))
            link_name = f"{idx:02d}-{os.path.basename(list_path)}"
            for group in groups:
                desired.setdefault(group, {})[link_name] = list_path

        existing_groups: set[str] = set()
        for name in os.listdir(rules_dir):
            p = os.path.join(rules_dir, name)
            if os.path.isdir(p) and not os.path.islink(p):
                existing_groups.add(name)
                if name not in desired:
                    try:
                        shutil.rmtree(p)
                    except Exception:
                        pass
            else:
                try:
                    os.unlink(p)
                except Exception:
                    pass

        for group_name in (existing_groups | set(desired.keys())):
            group_dir = os.path.join(rules_dir, group_name)
            desired_links = desired.get(group_name, {})
            if desired_links:
                os.makedirs(group_dir, mode=0o700, exist_ok=True)
            try:
                existing_entries = os.listdir(group_dir)
            except Exception:
                existing_entries = []

            for entry in existing_entries:
                entry_path = os.path.join(group_dir, entry)
                if entry not in desired_links:
                    try:
                        if os.path.isdir(entry_path) and not os.path.islink(entry_path):
                            shutil.rmtree(entry_path)
                        else:
                            os.unlink(entry_path)
                    except Exception:
                        pass
                    continue

                expected_target = desired_links[entry]
                in_sync = False
                try:
                    if os.path.islink(entry_path):
                        in_sync = os.path.realpath(entry_path) == os.path.realpath(expected_target)
                except Exception:
                    in_sync = False

                if not in_sync:
                    try:
                        if os.path.isdir(entry_path) and not os.path.islink(entry_path):
                            shutil.rmtree(entry_path)
                        else:
                            os.unlink(entry_path)
                    except Exception:
                        pass

            for link_name, target in desired_links.items():
                link_path = os.path.join(group_dir, link_name)
                if os.path.lexists(link_path):
                    continue
                try:
                    os.symlink(target, link_path)
                except Exception:
                    try:
                        shutil.copy2(target, link_path)
                    except Exception:
                        pass

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
            if self._cfg_action is not None:
                return

            menu = parent.actionsButton.menu()
            if menu is None:
                return

            icon_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "blocklist.svg")
            icon = QtGui.QIcon(icon_path) if os.path.exists(icon_path) else QtGui.QIcon()

            quit_action = self._find_quit_action(menu)
            if quit_action is not None:
                if not icon.isNull():
                    self._cfg_action = menu.addAction(icon, "List subscriptions")
                else:
                    self._cfg_action = menu.addAction("List subscriptions")
                menu.insertAction(quit_action, self._cfg_action)
            else:
                acts = menu.actions()
                if acts and not acts[-1].isSeparator():
                    menu.addSeparator()
                if not icon.isNull():
                    self._cfg_action = menu.addAction(icon, "List subscriptions")
                else:
                    self._cfg_action = menu.addAction("List subscriptions")

            self._cfg_action.triggered.connect(lambda *_: self._open_config_dialog(parent))

    def _find_quit_action(self, menu: Any):
        qt_key = getattr(getattr(QtCore, "Qt", object()), "Key", None)
        key_q = getattr(qt_key, "Key_Q", None) if qt_key is not None else None
        for act in menu.actions():
            if act.isSeparator():
                continue
            txt = (act.text() or "").replace("&", "").strip().lower()
            if txt == "quit":
                return act
            shortcut = act.shortcut()
            if key_q is not None and shortcut and shortcut.matches(QtGui.QKeySequence(key_q)):
                return act
        # In OpenSnitch main actions menu, Quit is typically the last entry.
        acts = [a for a in menu.actions() if not a.isSeparator()]
        if acts:
            return acts[-1]
        return None

    def _open_config_dialog(self, parent):
        from opensnitch.plugins.list_subscriptions import _gui

        appicon = None
        try:
            appicon = parent.windowIcon()
        except Exception:
            appicon = None

        if self._cfg_dialog is None:
            # Some wrapped dialog types are not accepted as QWidget parents by
            # PyQt6 constructors in plugin context. Use a top-level dialog.
            self._cfg_dialog = _gui.ListSubscriptionsDialog(parent=None, appicon=appicon)
        self._cfg_dialog.show()
        self._cfg_dialog.raise_()
        self._cfg_dialog.activateWindow()

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
        self._sync_sources_dirs()
        self._sync_global_symlinks()

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

        # Validate + force download all subscriptions at startup.
        th = threading.Thread(target=self._startup_recheck_all, daemon=True)
        th.start()

    def _startup_recheck_all(self):
        if self._config is None:
            return
        for sub in self._config.subscriptions:
            if not sub.enabled:
                continue
            try:
                self.force_refresh_subscription(sub)
            except Exception as e:
                logger.warning("list_subscriptions: startup recheck error name='%s' err=%s", sub.name, repr(e))
        self._sync_global_symlinks()

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
            logger.warning("list_subscriptions: skip '%s' (in backoff)", sub.name)
            return
        if not self._is_due(meta, sub):
            logger.warning("list_subscriptions: skip '%s' (not due yet)", sub.name)
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

    def force_refresh_subscription(self, sub: SubscriptionSpec):
        key = self._sub_key(sub)
        logger.warning(
            "list_subscriptions: force refresh requested name='%s' url='%s' file='%s'",
            sub.name, sub.url, sub.filename
        )
        ok = self.download(key, sub)
        logger.warning(
            "list_subscriptions: force refresh finished name='%s' result=%s",
            sub.name, "ok" if ok else "error"
        )
        self._sync_global_symlinks()
        return ok

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
        logger.warning(
            "list_subscriptions: download start key=%s name='%s' dst='%s'",
            key, sub.name, list_path
        )

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
                    logger.warning("list_subscriptions: download not-modified name='%s'", sub.name)
                    return True

                if r.status_code != 200:
                    self._mark_failure(meta, f"http_{r.status_code}")
                    self._save_meta(meta_path, meta)
                    self._resultsQueue.put((key, False, f"http_{r.status_code}"))
                    logger.warning("list_subscriptions: download http error name='%s' code=%s", sub.name, r.status_code)
                    return False

                cl: str | None = r.headers.get("Content-Length")
                if cl:
                    try:
                        if int(cl) > sub.max_bytes:
                            self._mark_failure(meta, f"too_large:{cl}")
                            self._save_meta(meta_path, meta)
                            self._resultsQueue.put((key, False, "too_large"))
                            logger.warning("list_subscriptions: download too-large name='%s' len=%s", sub.name, cl)
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
                        logger.warning("list_subscriptions: download bad-format name='%s'", sub.name)
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
                    logger.warning("list_subscriptions: download write-error name='%s' err=%s", sub.name, repr(e))
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
                logger.warning("list_subscriptions: download updated name='%s' bytes=%s", sub.name, downloaded)
                return True
            finally:
                r.close()
        except Exception as e:
            self._mark_failure(meta, repr(e))
            self._save_meta(meta_path, meta)
            self._resultsQueue.put((key, False, "unexpected_error"))
            logger.warning("list_subscriptions: download unexpected-error name='%s' err=%s", sub.name, repr(e))
            return False

        finally:
            lock.release()
