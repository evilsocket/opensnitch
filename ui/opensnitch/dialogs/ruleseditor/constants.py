classA_net = r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
classB_net = r'172\.1[6-9]\.\d+\.\d+|172\.2[0-9]\.\d+\.\d+|172\.3[0-1]+\.\d{1,3}\.\d{1,3}'
classC_net = r'192\.168\.\d{1,3}\.\d{1,3}'
others_net = r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}'
multinets = r'2[32][23459]\.\d{1,3}\.\d{1,3}\.\d{1,3}'
MULTICAST_RANGE = "^(" + multinets + ")$"
LAN_RANGES = "^(" + others_net + "|" + classC_net + "|" + classB_net + "|" + classA_net + "|::1|f[cde].*::.*)$"
LAN_LABEL = "LAN"
MULTICAST_LABEL = "MULTICAST"

INVALID_RULE_NAME_CHARS = '/'

ADD_RULE = 0
EDIT_RULE = 1
WORK_MODE = ADD_RULE

PW_USER = 0
PW_UID = 2

