import os
import re
from datetime import datetime
from typing import Any, Final
from urllib.parse import urlparse, unquote

from opensnitch.utils.xdg import xdg_config_home

ACTION_FILE: Final[str] = os.path.join(
    xdg_config_home, "opensnitch", "actions", "list_subscriptions.json"
)
DEFAULT_LISTS_DIR: Final[str] = os.path.join(
    xdg_config_home, "opensnitch", "list_subscriptions"
)
PLUGIN_DIR: Final[str] = os.path.abspath(os.path.dirname(__file__))
RES_DIR: Final[str] = os.path.join(PLUGIN_DIR, "res")

INTERVAL_UNITS: Final[tuple[str, ...]] = (
    "seconds",
    "minutes",
    "hours",
    "days",
    "weeks",
)
TIMEOUT_UNITS: Final[tuple[str, ...]] = ("seconds", "minutes", "hours", "days", "weeks")
SIZE_UNITS: Final[tuple[str, ...]] = ("bytes", "KB", "MB", "GB")
TIME_MULT: Final[dict[str, int]] = {
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
SHORT_TIME_MULT: Final[dict[str, int]] = {
    "s": TIME_MULT["seconds"],
    "m": TIME_MULT["minutes"],
    "h": TIME_MULT["hours"],
    "d": TIME_MULT["days"],
    "w": TIME_MULT["weeks"],
}
SIZE_MULT: Final[dict[str, int]] = {
    "bytes": 1,
    "kb": 1024,
    "mb": 1024 * 1024,
    "gb": 1024 * 1024 * 1024,
}

DEFAULT_UA: Final[str] = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0"
)

DEFAULT_NOTIFY_CONFIG: Final[dict[str, dict[str, str]]] = {
    "success": {"desktop": "Lists subscriptions updated"},
    "error": {"desktop": "Error updating lists subscriptions"},
}


def now_iso():
    return datetime.now().astimezone().isoformat()


def parse_iso(ts: str):
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def normalize_iso_timestamp(value: Any, fallback: str | None = None):
    text = str(value or "").strip()
    if text != "" and parse_iso(text) is not None:
        return text
    if fallback:
        return fallback
    return now_iso()


def opt_int(value: Any):
    try:
        return int(value) if value is not None else None
    except Exception:
        return None


def opt_str(value: Any):
    try:
        if value is None:
            return None
        normalized = (str(value) or "").strip().lower()
        return normalized if normalized != "" else None
    except Exception:
        return None


def display_str(value: Any):
    if value is None:
        return ""
    return str(value)


def strip_or_none(value: Any):
    text = str(value or "").strip()
    return text or None


def normalize_lists_dir(path: str | None):
    default_dir = os.path.join(xdg_config_home, "opensnitch", "list_subscriptions")
    raw = (path or "").strip()
    if raw == "":
        raw = default_dir
    expanded = os.path.expandvars(os.path.expanduser(raw))
    if not os.path.isabs(expanded):
        return os.path.abspath(expanded)
    return expanded


def is_valid_url(value: str | None):
    parsed = urlparse(str(value or "").strip())
    return parsed.scheme in {"http", "https"} and parsed.netloc != ""


def safe_filename(value: Any):
    return os.path.basename((str(value or "")).strip())


def normalized_list_type(value: str | None):
    return (value or "hosts").strip().lower()


def filename_from_url(url: str | None):
    try:
        parsed = urlparse((url or "").strip())
        return safe_filename(unquote(parsed.path or ""))
    except Exception:
        return ""


def slugify_name(name: str | None):
    raw = (name or "").strip().lower()
    if raw == "":
        return "subscription.list"
    slug = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-._")
    if slug == "":
        slug = "subscription"
    if "." not in slug:
        slug += ".list"
    return safe_filename(slug)


def deslugify_filename(filename: str | None, list_type: str | None):
    safe = safe_filename(filename)
    base, _ext = os.path.splitext(safe)
    suffix = f"-{normalized_list_type(list_type)}"
    if base.lower().endswith(suffix):
        base = base[: -len(suffix)]
    pretty = re.sub(r"[-_.]+", " ", base).strip()
    pretty = re.sub(r"\s+", " ", pretty)
    if pretty == "":
        return safe
    return pretty.title()


def filename_from_content_disposition(value: str | None):
    cd = str(value or "").strip()
    if cd == "":
        return ""
    filename = ""
    m_star = re.search(
        r'filename\*\s*=\s*[^\'";]+\'[^\'";]*\'([^;]+)', cd, re.IGNORECASE
    )
    if m_star:
        filename = unquote(m_star.group(1).strip().strip('"'))
    if filename == "":
        params = {}
        try:
            raw_params = ";".join(cd.split(";")[1:])
            for part in raw_params.split(";"):
                if "=" not in part:
                    continue
                key, raw_value = part.split("=", 1)
                params[key.strip().lower()] = raw_value.strip().strip('"')
        except Exception:
            params = {}
        raw = params.get("filename")
        if raw:
            filename = unquote(str(raw)).strip()
    return safe_filename(filename)


def derive_filename(
    name: str | None,
    url: str | None,
    filename: str | None,
    header_filename: str | None = None,
):
    fn = safe_filename(header_filename)
    if fn != "":
        return fn
    fn = safe_filename(filename)
    if fn != "":
        return fn
    fn = filename_from_url(url)
    if fn != "":
        return fn
    return slugify_name(name)


def ensure_filename_type_suffix(filename: str, list_type: str):
    fn = safe_filename(filename)
    base, ext = os.path.splitext(fn)
    ltype = normalized_list_type(list_type)
    suffix = f"-{ltype}"
    if not base.lower().endswith(suffix):
        base = f"{base}{suffix}" if base else ltype
    if ext == "":
        ext = ".txt"
    return safe_filename(f"{base}{ext}")


def normalized_subscription_filename(filename: str | None, list_type: str | None):
    safe_name = safe_filename(filename)
    if safe_name == "":
        safe_name = "subscription.list"
    return ensure_filename_type_suffix(safe_name, normalized_list_type(list_type))


def subscription_dirname(filename: str | None, list_type: str | None):
    safe_name = normalized_subscription_filename(filename, list_type)
    base, _ext = os.path.splitext(safe_name)
    normalized_type = normalized_list_type(list_type)
    suffix = f"-{normalized_type}"
    dirname = base if base else "subscription"
    if not dirname.lower().endswith(suffix):
        dirname = f"{dirname}{suffix}"
    return dirname


def list_file_path(lists_dir: str, filename: str | None, list_type: str | None):
    safe_name = normalized_subscription_filename(filename, list_type)
    return os.path.join(lists_dir, "sources.list.d", safe_name)


def subscription_rule_dir(lists_dir: str, filename: str | None, list_type: str | None):
    return os.path.join(
        lists_dir,
        "rules.list.d",
        subscription_dirname(filename, list_type),
    )


def normalize_unit(value: str | None, allowed: tuple[str, ...], fallback: str):
    normalized = (value or "").strip().lower()
    for unit in allowed:
        if unit.lower() == normalized:
            return unit
    return fallback


def timestamp_sort_key(value: str | None):
    normalized = str(value or "").strip()
    return (normalized == "", normalized)


def normalize_group(group: str | None):
    raw = (group or "").strip().lower()
    if raw == "":
        return ""
    raw = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-._")
    return raw


def normalize_groups(groups: Any):
    out: list[str] = []
    if isinstance(groups, (list, tuple, set)):
        raw_items = [str(x) for x in groups]
    else:
        raw_items = str(groups or "").split(",")
    seen: set[str] = set()
    for item in raw_items:
        g = normalize_group(item)
        if g == "" or g == "all" or g in seen:
            continue
        seen.add(g)
        out.append(g)
    return out


def dedupe_subscription_identity(
    filename: str,
    name: str,
    url: str,
    list_type: str,
    seen_filenames: dict[str, str] | None,
):
    if seen_filenames is None:
        return filename, name, False

    key = filename
    seen_url = seen_filenames.get(key)
    if seen_url is None:
        seen_filenames[key] = url
        return filename, name, False
    if seen_url == url:
        return filename, name, True

    base, ext = os.path.splitext(filename)
    if ext == "":
        ext = ".txt"
    suffix = f"-{normalized_list_type(list_type)}"
    root = base
    if root.lower().endswith(suffix):
        root = root[: -len(suffix)]
    root = root.rstrip("-")
    n = 2
    candidate = filename
    while candidate in seen_filenames:
        candidate = f"{root}-{n}{suffix}{ext}"
        n += 1
    display_name = (name or "").strip()
    if display_name == "":
        display_name = root or "subscription"
    seen_filenames[candidate] = url
    return candidate, f"{display_name} ({n - 1})", False


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
