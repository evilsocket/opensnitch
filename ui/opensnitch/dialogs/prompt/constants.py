from PyQt6.QtCore import QCoreApplication as QC

# the fields a connection can be matched on, and the patterns built out of
# them, are defined in opensnitch.operands, so that opensnitch-cli can reuse
# them without pulling in Qt. Re-exported here for convenience.
from opensnitch.operands import (
    FIELD_REGEX_HOST, FIELD_REGEX_IP, FIELD_PROC_PATH, FIELD_PROC_ARGS,
    FIELD_PROC_ID, FIELD_USER_ID, FIELD_DST_IP, FIELD_DST_PORT,
    FIELD_DST_NETWORK, FIELD_DST_HOST, FIELD_APPIMAGE, FIELD_SNAP,
    APPIMAGE_PREFIX, SNAP_PREFIX
)

# re-exported, so that the rest of the pop-up keeps using constants.FIELD_*
__all__ = [
    "FIELD_REGEX_HOST", "FIELD_REGEX_IP", "FIELD_PROC_PATH", "FIELD_PROC_ARGS",
    "FIELD_PROC_ID", "FIELD_USER_ID", "FIELD_DST_IP", "FIELD_DST_PORT",
    "FIELD_DST_NETWORK", "FIELD_DST_HOST", "FIELD_APPIMAGE", "FIELD_SNAP",
    "APPIMAGE_PREFIX", "SNAP_PREFIX",
]

PAGE_MAIN = 2
PAGE_DETAILS = 0
PAGE_CHECKSUMS = 1

WARNING_LABEL = "#warning-checksum"

DEFAULT_TIMEOUT = 15

TARGET_IDX_PROC_PATH = 0
TARGET_IDX_PROC_CMDLINE = 1
TARGET_IDX_DST_PORT = 2
TARGET_IDX_DST_IP = 3
TARGET_IDX_UID = 4
TARGET_IDX_PID = 5

DURATION_30s    = "30s"
DURATION_5m     = "5m"
DURATION_15m    = "15m"
DURATION_30m    = "30m"
DURATION_1h     = "1h"
DURATION_12h     = "12h"
# don't translate

# label displayed in the pop-up combo
DURATION_session = QC.translate("popups", "until reboot")
# label displayed in the pop-up combo
DURATION_forever = QC.translate("popups", "forever")

DSTIP_LBL_CLICKED=0
DSTPORT_LBL_CLICKED=1
USER_LBL_CLICKED=2
CHECKSUM_LBL_CLICKED=3
