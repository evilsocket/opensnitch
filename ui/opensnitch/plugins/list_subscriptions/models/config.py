from opensnitch.plugins.list_subscriptions._utils import DEFAULT_NOTIFY_CONFIG, DEFAULT_UA, normalize_lists_dir
from opensnitch.plugins.list_subscriptions.models.global_defaults import GlobalDefaults
from opensnitch.plugins.list_subscriptions.models.subscriptions import MutableSubscriptionSpec, SubscriptionSpec, normalize_subscription_identities


from dataclasses import dataclass, field, replace
from typing import Any


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
