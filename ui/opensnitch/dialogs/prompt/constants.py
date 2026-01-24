from PyQt6.QtCore import QCoreApplication as QC

PAGE_MAIN = 2
PAGE_DETAILS = 0
PAGE_CHECKSUMS = 1

WARNING_LABEL = "#warning-checksum"

DEFAULT_TIMEOUT = 15

# don't translate
FIELD_REGEX_HOST    = "regex_host"
FIELD_REGEX_IP      = "regex_ip"
FIELD_PROC_PATH     = "process_path"
FIELD_PROC_ARGS     = "process_args"
FIELD_PROC_ID       = "process_id"
FIELD_USER_ID       = "user_id"
FIELD_DST_IP        = "dst_ip"
FIELD_DST_PORT      = "dst_port"
FIELD_DST_NETWORK   = "dst_network"
FIELD_DST_HOST      = "simple_host"
FIELD_APPIMAGE      = "appimage_path"
FIELD_SNAP          = "snap_path"

DURATION_30s    = "30s"
DURATION_5m     = "5m"
DURATION_15m    = "15m"
DURATION_30m    = "30m"
DURATION_1h     = "1h"
DURATION_12h     = "12h"
# don't translate

APPIMAGE_PREFIX = "/tmp/.mount_"
SNAP_PREFIX = "/snap"
FULL_COMMAND_BIN = ["python", "curl", "wget", "node", "java", "ssh"]

# label displayed in the pop-up combo
DURATION_session = QC.translate("popups", "until reboot")
# label displayed in the pop-up combo
DURATION_forever = QC.translate("popups", "forever")

DSTIP_LBL_CLICKED=0
DSTPORT_LBL_CLICKED=1
USER_LBL_CLICKED=2
CHECKSUM_LBL_CLICKED=3
