from opensnitch.plugins.list_subscriptions._utils import DEFAULT_UA, normalize_lists_dir


from dataclasses import dataclass
from typing import Any


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