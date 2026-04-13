from opensnitch.plugins.list_subscriptions._utils import normalize_iso_timestamp, now_iso
from opensnitch.plugins.list_subscriptions.models.config import MutablePluginConfig


from dataclasses import dataclass, field
from typing import Any


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