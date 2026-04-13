from dataclasses import asdict, dataclass
from typing import Any


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