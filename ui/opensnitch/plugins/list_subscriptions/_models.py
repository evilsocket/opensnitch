import os
import re
from dataclasses import dataclass, field, asdict, replace
from typing import Any
from urllib.parse import urlparse, unquote

from opensnitch.utils.xdg import xdg_config_home
from opensnitch.plugins.list_subscriptions._utils import (
    to_seconds,
    parse_compact_duration,
    to_max_bytes,
)


DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0 Safari/537.36"
)


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
    raw = (group or "all").strip().lower()
    raw = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-._")
    return raw if raw else "all"


def normalize_groups(groups: Any) -> list[str]:
    out: list[str] = []
    if isinstance(groups, (list, tuple, set)):
        raw_items = [str(x) for x in groups]
    else:
        raw_items = str(groups or "").split(",")
    seen: set[str] = set()
    for item in raw_items:
        g = normalize_group(item)
        if g in seen:
            continue
        seen.add(g)
        out.append(g)
    return out if out else ["all"]


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
        lists_dir = normalize_lists_dir(str(d.get("lists_dir") or lists_dir or ""))

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
    groups: tuple[str, ...] = ("all",)
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
        list_type = str(d.get("format", "hosts") or "hosts").strip().lower()
        filename = derive_filename(name, url, d.get("filename"))
        filename = ensure_filename_type_suffix(filename, list_type)
        groups_raw = d.get("groups")
        if "group" in d:
            legacy_group = d.get("group")
            if isinstance(groups_raw, (list, tuple, set)):
                groups_raw = list(groups_raw) + [legacy_group]
            elif groups_raw is None:
                groups_raw = [legacy_group]
            else:
                groups_raw = [groups_raw, legacy_group]
        groups = normalize_groups(groups_raw)
        if "all" not in groups:
            groups.insert(0, "all")
        if not url:
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
            groups=tuple(groups),
            enabled=bool(d.get("enabled", True)),
            format=list_type,
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


@dataclass
class MutableSubscriptionSpec:
    name: str = ""
    url: str = ""
    filename: str = ""
    groups: list[str] = field(default_factory=lambda: ["all"])
    enabled: bool = True
    format: str = "hosts"
    interval: int = 24
    interval_units: str = "hours"
    timeout: int = 60
    timeout_units: str = "seconds"
    max_size: int = 20
    max_size_units: str = "MB"

    @staticmethod
    def from_spec(spec: SubscriptionSpec):
        return MutableSubscriptionSpec(
            name=spec.name,
            url=spec.url,
            filename=spec.filename,
            groups=list(spec.groups),
            enabled=spec.enabled,
            format=spec.format,
            interval=spec.interval,
            interval_units=spec.interval_units,
            timeout=spec.timeout,
            timeout_units=spec.timeout_units,
            max_size=spec.max_size,
            max_size_units=spec.max_size_units,
        )

    @staticmethod
    def from_dict(d: dict[str, Any], defaults: GlobalDefaults):
        spec = SubscriptionSpec.from_dict(d, defaults)
        if spec is None:
            return None
        return MutableSubscriptionSpec.from_spec(spec)

    def to_dict(self):
        return {
            "enabled": bool(self.enabled),
            "name": (self.name or "").strip(),
            "url": (self.url or "").strip(),
            "filename": safe_filename(self.filename),
            "format": (self.format or "hosts").strip().lower(),
            "groups": normalize_groups(self.groups),
            "interval": int(self.interval),
            "interval_units": (self.interval_units or "hours").strip().lower(),
            "timeout": int(self.timeout),
            "timeout_units": (self.timeout_units or "seconds").strip().lower(),
            "max_size": int(self.max_size),
            "max_size_units": (self.max_size_units or "MB").strip(),
        }


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
        seen_filenames: set[str] = set()
        for item in (raw_cfg.get("subscriptions") or []):
            sub = SubscriptionSpec.from_dict(item, defaults)
            if sub is not None:
                key = os.path.normcase(sub.filename)
                if key in seen_filenames:
                    base, ext = os.path.splitext(sub.filename)
                    n = 2
                    candidate = sub.filename
                    while os.path.normcase(candidate) in seen_filenames:
                        suffix = f"-{n}"
                        candidate = f"{base}{suffix}{ext}" if ext else f"{base}{suffix}"
                        n += 1
                    sub = replace(sub, filename=candidate)
                    if sub.name.strip() == "" or sub.name == sub.filename:
                        sub = replace(sub, name=candidate)
                    key = os.path.normcase(sub.filename)
                seen_filenames.add(key)
                subs.append(sub)

        return PluginConfig(defaults=defaults, subscriptions=subs)


@dataclass
class MutableActionConfig:
    enabled: bool = False
    defaults: GlobalDefaults = field(default_factory=lambda: GlobalDefaults.from_dict({}))
    subscriptions: list[MutableSubscriptionSpec] = field(default_factory=list)
    action_name: str = "listSubscriptionsActions"
    created: str = ""
    updated: str = ""
    description: str = "Manage and auto-update blocklist subscriptions (hosts format)"
    types: list[str] = field(default_factory=lambda: ["global", "main-dialog"])

    @staticmethod
    def from_action_dict(raw_action: dict[str, Any], lists_dir: str | None = None):
        action_name = str(raw_action.get("name", "listSubscriptionsActions"))
        created = str(raw_action.get("created", ""))
        updated = str(raw_action.get("updated", ""))
        description = str(raw_action.get("description", "Manage and auto-update blocklist subscriptions (hosts format)"))
        action_types_raw = raw_action.get("type", ["global", "main-dialog"])
        if isinstance(action_types_raw, list):
            action_types = [str(t) for t in action_types_raw]
        else:
            action_types = ["global", "main-dialog"]

        actions_obj = raw_action.get("actions", {})
        action_cfg = actions_obj.get("list_subscriptions", {}) if isinstance(actions_obj, dict) else {}
        plugin_cfg_raw = action_cfg.get("config", {}) if isinstance(action_cfg, dict) else {}
        plugin_cfg = plugin_cfg_raw if isinstance(plugin_cfg_raw, dict) else {}
        compiled_cfg = PluginConfig.from_dict(plugin_cfg, lists_dir=plugin_cfg.get("lists_dir") or lists_dir)
        enabled = bool(action_cfg.get("enabled", False)) if isinstance(action_cfg, dict) else False

        return MutableActionConfig(
            enabled=enabled,
            defaults=compiled_cfg.defaults,
            subscriptions=[MutableSubscriptionSpec.from_spec(s) for s in compiled_cfg.subscriptions],
            action_name=action_name,
            created=created,
            updated=updated,
            description=description,
            types=action_types,
        )

    @staticmethod
    def default(lists_dir: str | None = None):
        defaults = GlobalDefaults.from_dict(
            {
                "interval": 24,
                "interval_units": "hours",
                "timeout": 20,
                "timeout_units": "seconds",
                "max_size": 50,
                "max_size_units": "MB",
            },
            lists_dir=lists_dir,
        )
        return MutableActionConfig(
            enabled=True,
            defaults=defaults,
            subscriptions=[],
        )

    def to_plugin_dict(self):
        return {
            "lists_dir": normalize_lists_dir(self.defaults.lists_dir),
            "interval": int(self.defaults.interval),
            "interval_units": self.defaults.interval_units,
            "timeout": int(self.defaults.timeout),
            "timeout_units": self.defaults.timeout_units,
            "max_size": int(self.defaults.max_size),
            "max_size_units": self.defaults.max_size_units,
            "user_agent": self.defaults.user_agent if self.defaults.user_agent is not None else DEFAULT_UA,
            "subscriptions": [sub.to_dict() for sub in self.subscriptions],
            "notify": {
                "success": {"desktop": "Lists subscriptions updated"},
                "error": {"desktop": "Error updating lists subscriptions"},
            },
        }

    def to_action_dict(self):
        return {
            "name": self.action_name,
            "created": self.created,
            "updated": self.updated,
            "description": self.description,
            "type": list(self.types),
            "actions": {
                "list_subscriptions": {
                    "enabled": bool(self.enabled),
                    "config": self.to_plugin_dict(),
                }
            },
        }


@dataclass
class ListMetadata:
    version: int = 1
    url: str = ""
    format: str = "hosts"
    etag: str = ""
    last_modified: str = ""
    last_checked: str = ""
    last_updated: str = ""
    backoff_until: str = ""
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
