from typing import TypedDict
from enum import IntEnum

class SubscriptionEventItem(TypedDict, total=False):
    key: str
    name: str
    url: str
    filename: str
    format: str
    state: str | None
    path: str | None


class SubscriptionEventPayload(TypedDict, total=False):
    enabled: bool
    name: str
    url: str
    filename: str
    format: str
    groups: list[str]
    interval: int | None
    interval_units: str | None
    timeout: int | None
    timeout_units: str | None
    max_size: int | None
    max_size_units: str | None


class RuntimeEventType(IntEnum):
    RUNTIME_ENABLED = 1
    CONFIG_RELOADED = 2
    RUNTIME_DISABLED = 3
    RUNTIME_STOPPED = 4
    RUNTIME_ERROR = 5
    DOWNLOAD_STARTED = 6
    DOWNLOAD_FINISHED = 7
    DOWNLOAD_FAILED = 8
    FILE_SAVE_FINISHED = 9
    FILE_SAVE_ERROR = 10
    FILE_LOAD_FINISHED = 11
    FILE_LOAD_ERROR = 12