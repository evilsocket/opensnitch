from dataclasses import dataclass, field, asdict, replace
from typing import Any, TypeVar
from collections.abc import Callable

from opensnitch.plugins.list_subscriptions._utils import (
    dedupe_subscription_identity,
    derive_filename,
    ensure_filename_type_suffix,
    normalize_groups,
    normalize_lists_dir,
    now_iso,
    normalize_iso_timestamp,
    opt_int,
    opt_str,
    parse_compact_duration,
    safe_filename,
    to_seconds,
    to_max_bytes,
)


DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0"

DEFAULT_NOTIFY_CONFIG = {
    "success": {"desktop": "Lists subscriptions updated"},
    "error": {"desktop": "Error updating lists subscriptions"},
}

SubscriptionLike = TypeVar(
    "SubscriptionLike", "SubscriptionSpec", "MutableSubscriptionSpec"
)


def normalize_subscription_identities(
    subscriptions: list[SubscriptionLike],
    invalidate_duplicates: bool = False,
    clone: (
        Callable[[SubscriptionLike, str, str, str, str], SubscriptionLike] | None
    ) = None,
):
    normalized: list[SubscriptionLike] = []
    seen_filenames: dict[str, str] = {}
    for sub in subscriptions:
        url = (sub.url or "").strip()
        if url == "":
            return None
        list_type = (sub.format or "hosts").strip().lower()
        filename = ensure_filename_type_suffix(
            derive_filename(sub.name, url, sub.filename), list_type
        )
        name = (sub.name or "").strip() or filename
        filename, name, duplicate_same_url = dedupe_subscription_identity(
            filename,
            name,
            url,
            list_type,
            seen_filenames,
        )
        if duplicate_same_url and invalidate_duplicates:
            return None
        if clone is None:
            normalized.append(sub)
        else:
            normalized.append(clone(sub, name, url, filename, list_type))
    return normalized


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
    groups: tuple[str, ...] = ()
    enabled: bool = True
    format: str = "hosts"
    interval: int | None = None
    interval_units: str | None = None
    timeout: int | None = None
    timeout_units: str | None = None
    max_size: int | None = None
    max_size_units: str | None = None
    interval_seconds: int = 24 * 3600
    timeout_seconds: int = 60
    max_bytes: int = 20 * 1024 * 1024

    @staticmethod
    def from_dict(
        d: dict[str, Any] | None,
        defaults: GlobalDefaults | None = None,
        require_url: bool = True,
        ensure_suffix: bool = True,
    ):
        d = d or {}
        defaults = defaults or GlobalDefaults.from_dict({})

        name = (d.get("name") or "").strip()
        url = (d.get("url") or "").strip()
        list_type = str(d.get("format", "hosts") or "hosts").strip().lower()
        filename = derive_filename(name, url, d.get("filename"))
        if ensure_suffix and filename != "":
            filename = ensure_filename_type_suffix(filename, list_type)
        elif not ensure_suffix and filename == "":
            filename = ""
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
        if require_url and not url:
            return None
        if require_url and not name:
            name = filename

        interval_raw: Any = d.get("interval")
        timeout_raw: Any = d.get("timeout")
        interval_units_raw: Any = d.get("interval_units")
        timeout_units_raw: Any = d.get("timeout_units")

        interval = opt_int(interval_raw)
        interval_units_opt = opt_str(interval_units_raw)
        interval_units = interval_units_opt
        timeout = opt_int(timeout_raw)
        timeout_units_opt = opt_str(timeout_units_raw)
        timeout_units = timeout_units_opt
        max_size = opt_int(d.get("max_size"))
        max_size_units = opt_str(d.get("max_size_units"))

        default_interval_seconds = to_seconds(
            defaults.interval, defaults.interval_units, 24 * 3600
        )
        default_timeout_seconds = to_seconds(
            defaults.timeout, defaults.timeout_units, 60
        )
        default_max_bytes = to_max_bytes(
            defaults.max_size, defaults.max_size_units, 20 * 1024 * 1024
        )

        effective_interval = interval if interval is not None else defaults.interval
        effective_interval_units = interval_units or defaults.interval_units
        effective_timeout = timeout if timeout is not None else defaults.timeout
        effective_timeout_units = timeout_units or defaults.timeout_units
        effective_max_size = max_size if max_size is not None else defaults.max_size
        effective_max_size_units = max_size_units or defaults.max_size_units

        interval_seconds: int | None = None
        interval_is_composite = False
        if interval_units_opt is None:
            interval_seconds = parse_compact_duration(interval_raw)
            interval_is_composite = interval_seconds is not None
        if interval_seconds is None:
            interval_seconds = to_seconds(
                effective_interval, effective_interval_units, default_interval_seconds
            )
        elif interval_is_composite:
            interval = interval_seconds
            interval_units = "composite"

        timeout_seconds: int | None = None
        timeout_is_composite = False
        if timeout_units_opt is None:
            timeout_seconds = parse_compact_duration(timeout_raw)
            timeout_is_composite = timeout_seconds is not None
        if timeout_seconds is None:
            timeout_seconds = to_seconds(
                effective_timeout, effective_timeout_units, default_timeout_seconds
            )
        elif timeout_is_composite:
            timeout = timeout_seconds
            timeout_units = "composite"

        max_bytes = to_max_bytes(
            effective_max_size, effective_max_size_units, default_max_bytes
        )

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
    groups: list[str] = field(default_factory=list)
    enabled: bool = True
    format: str = "hosts"
    interval: int | None = None
    interval_units: str | None = None
    timeout: int | None = None
    timeout_units: str | None = None
    max_size: int | None = None
    max_size_units: str | None = None

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
    def from_dict(
        d: dict[str, Any] | None,
        defaults: GlobalDefaults | None = None,
        require_url: bool = True,
        ensure_suffix: bool = True,
    ):
        spec = SubscriptionSpec.from_dict(
            d,
            defaults,
            require_url=require_url,
            ensure_suffix=ensure_suffix,
        )
        if spec is None:
            return None

        d = d or {}

        def _has_value(value: Any):
            return value is not None and str(value).strip() != ""

        return MutableSubscriptionSpec(
            name=spec.name,
            url=spec.url,
            filename=spec.filename,
            groups=list(spec.groups),
            enabled=spec.enabled,
            format=spec.format,
            interval=(
                spec.interval
                if _has_value(d.get("interval")) or spec.interval_units == "composite"
                else None
            ),
            interval_units=(
                spec.interval_units
                if _has_value(d.get("interval_units"))
                or spec.interval_units == "composite"
                else None
            ),
            timeout=(
                spec.timeout
                if _has_value(d.get("timeout")) or spec.timeout_units == "composite"
                else None
            ),
            timeout_units=(
                spec.timeout_units
                if _has_value(d.get("timeout_units"))
                or spec.timeout_units == "composite"
                else None
            ),
            max_size=spec.max_size if _has_value(d.get("max_size")) else None,
            max_size_units=(
                spec.max_size_units if _has_value(d.get("max_size_units")) else None
            ),
        )

    def to_dict(self):
        data: dict[str, Any] = {
            "enabled": bool(self.enabled),
            "name": (self.name or "").strip(),
            "url": (self.url or "").strip(),
            "filename": safe_filename(self.filename),
            "format": (self.format or "hosts").strip().lower(),
            "groups": normalize_groups(self.groups),
        }
        if self.interval is not None:
            data["interval"] = int(self.interval)
            data["interval_units"] = (self.interval_units or "hours").strip().lower()
        if self.timeout is not None:
            data["timeout"] = int(self.timeout)
            data["timeout_units"] = (self.timeout_units or "seconds").strip().lower()
        if self.max_size is not None:
            data["max_size"] = int(self.max_size)
            data["max_size_units"] = (self.max_size_units or "MB").strip()
        return data


@dataclass(frozen=True)
class PluginConfig:
    defaults: GlobalDefaults = field(
        default_factory=lambda: GlobalDefaults.from_dict({})
    )
    subscriptions: list[SubscriptionSpec] = field(default_factory=list)
    notify: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_NOTIFY_CONFIG))

    @staticmethod
    def from_dict(
        raw_cfg: dict[str, Any],
        lists_dir: str | None = None,
        invalidate_duplicates: bool = False,
    ):
        raw_cfg = raw_cfg or {}
        if not isinstance(raw_cfg, dict):
            raw_cfg = {}
        defaults = GlobalDefaults.from_dict(raw_cfg, lists_dir)

        subs: list[SubscriptionSpec] = []
        for item in raw_cfg.get("subscriptions") or []:
            sub = SubscriptionSpec.from_dict(
                item,
                defaults,
            )
            if sub is not None:
                subs.append(sub)

        normalized_subs = normalize_subscription_identities(
            subs,
            invalidate_duplicates=invalidate_duplicates,
            clone=lambda sub, name, url, filename, list_type: replace(
                sub,
                name=name,
                url=url,
                filename=filename,
                format=list_type,
            ),
        )
        if normalized_subs is None:
            normalized_subs = []

        notify = raw_cfg.get("notify")
        if not isinstance(notify, dict):
            notify = dict(DEFAULT_NOTIFY_CONFIG)

        return PluginConfig(
            defaults=defaults, subscriptions=normalized_subs, notify=notify
        )


@dataclass
class MutablePluginConfig:
    defaults: GlobalDefaults = field(
        default_factory=lambda: GlobalDefaults.from_dict({})
    )
    subscriptions: list[MutableSubscriptionSpec] = field(default_factory=list)
    notify: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_NOTIFY_CONFIG))

    @staticmethod
    def from_plugin_config(config: PluginConfig):
        return MutablePluginConfig(
            defaults=config.defaults,
            subscriptions=[
                MutableSubscriptionSpec.from_spec(sub) for sub in config.subscriptions
            ],
            notify=dict(config.notify),
        )

    @staticmethod
    def from_dict(raw_cfg: dict[str, Any], lists_dir: str | None = None):
        compiled_cfg = PluginConfig.from_dict(raw_cfg, lists_dir=lists_dir)
        return MutablePluginConfig.from_plugin_config(compiled_cfg)

    @staticmethod
    def default(lists_dir: str | None = None):
        return MutablePluginConfig(
            defaults=GlobalDefaults.from_dict({}, lists_dir=lists_dir),
            subscriptions=[],
            notify=dict(DEFAULT_NOTIFY_CONFIG),
        )

    def normalize_subscriptions(self, invalidate_duplicates: bool = False):
        normalized = normalize_subscription_identities(
            self.subscriptions,
            invalidate_duplicates=invalidate_duplicates,
            clone=lambda sub, name, url, filename, list_type: MutableSubscriptionSpec(
                name=name,
                url=url,
                filename=filename,
                groups=list(sub.groups),
                enabled=sub.enabled,
                format=list_type,
                interval=sub.interval,
                interval_units=sub.interval_units,
                timeout=sub.timeout,
                timeout_units=sub.timeout_units,
                max_size=sub.max_size,
                max_size_units=sub.max_size_units,
            ),
        )
        if normalized is None:
            return None
        self.subscriptions = normalized
        return normalized

    def to_dict(self):
        return {
            "lists_dir": normalize_lists_dir(self.defaults.lists_dir),
            "interval": int(self.defaults.interval),
            "interval_units": self.defaults.interval_units,
            "timeout": int(self.defaults.timeout),
            "timeout_units": self.defaults.timeout_units,
            "max_size": int(self.defaults.max_size),
            "max_size_units": self.defaults.max_size_units,
            "user_agent": (
                self.defaults.user_agent
                if self.defaults.user_agent is not None
                else DEFAULT_UA
            ),
            "subscriptions": [sub.to_dict() for sub in self.subscriptions],
            "notify": self.notify,
        }


@dataclass
class MutableActionConfig:
    enabled: bool = False
    plugin: MutablePluginConfig = field(default_factory=MutablePluginConfig.default)
    action_name: str = "listSubscriptionsActions"
    created: str = ""
    updated: str = ""
    description: str = "Manage and auto-update blocklist subscriptions (hosts format)"
    types: list[str] = field(default_factory=lambda: ["global", "main-dialog"])

    @staticmethod
    def from_action_dict(raw_action: dict[str, Any], lists_dir: str | None = None):
        action_name = str(raw_action.get("name", "listSubscriptionsActions"))
        created = normalize_iso_timestamp(raw_action.get("created"))
        updated = normalize_iso_timestamp(raw_action.get("updated"), fallback=created)
        description = str(
            raw_action.get(
                "description",
                "Manage and auto-update blocklist subscriptions (hosts format)",
            )
        )
        action_types_raw = raw_action.get("type", ["global", "main-dialog"])
        if isinstance(action_types_raw, list):
            action_types = [str(t) for t in action_types_raw]
        else:
            action_types = ["global", "main-dialog"]

        actions_obj = raw_action.get("actions", {})
        action_cfg = (
            actions_obj.get("list_subscriptions", {})
            if isinstance(actions_obj, dict)
            else {}
        )
        plugin_cfg_raw = (
            action_cfg.get("config", {}) if isinstance(action_cfg, dict) else {}
        )
        plugin_cfg = plugin_cfg_raw if isinstance(plugin_cfg_raw, dict) else {}
        mutable_plugin = MutablePluginConfig.from_dict(
            plugin_cfg, lists_dir=plugin_cfg.get("lists_dir") or lists_dir
        )
        enabled = (
            bool(action_cfg.get("enabled", False))
            if isinstance(action_cfg, dict)
            else False
        )

        return MutableActionConfig(
            enabled=enabled,
            plugin=mutable_plugin,
            action_name=action_name,
            created=created,
            updated=updated,
            description=description,
            types=action_types,
        )

    @staticmethod
    def default(lists_dir: str | None = None):
        created = now_iso()
        return MutableActionConfig(
            enabled=True,
            plugin=MutablePluginConfig.default(lists_dir),
            created=created,
            updated=created,
        )

    def to_action_dict(self):
        created = normalize_iso_timestamp(self.created)
        updated = now_iso()
        self.created = created
        self.updated = updated
        return {
            "name": self.action_name,
            "created": created,
            "updated": updated,
            "description": self.description,
            "type": list(self.types),
            "actions": {
                "list_subscriptions": {
                    "enabled": bool(self.enabled),
                    "config": self.plugin.to_dict(),
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
