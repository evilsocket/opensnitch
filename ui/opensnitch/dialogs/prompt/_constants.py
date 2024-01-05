from PyQt5.QtCore import QCoreApplication as QC

PAGE_MAIN = 2
PAGE_DETAILS = 0
PAGE_CHECKSUMS = 1

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

DURATION_30s    = "30s"
DURATION_5m     = "5m"
DURATION_15m    = "15m"
DURATION_30m    = "30m"
DURATION_1h     = "1h"
# don't translate

APPIMAGE_PREFIX = "/tmp/.mount_"

# label displayed in the pop-up combo
DURATION_session = QC.translate("popups", "until reboot")
# label displayed in the pop-up combo
DURATION_forever = QC.translate("popups", "forever")
