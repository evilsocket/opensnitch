from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from opensnitch.plugins.list_subscriptions._utils import dedupe_subscription_identity, derive_filename, ensure_filename_type_suffix, normalize_groups, opt_int, opt_str, parse_compact_duration, safe_filename, to_max_bytes, to_seconds
from opensnitch.plugins.list_subscriptions.models.global_defaults import GlobalDefaults

SubscriptionLike = TypeVar(
    "SubscriptionLike", "SubscriptionSpec", "MutableSubscriptionSpec"
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
