
from opensnitch import ui_pb2
from .enums import *

class Expr():
    """
    Expr returns a new nftables expression that defines a match or an action:
        tcp dport 22, udp sport 53
        log prefix "xxx"

    Attributes:
        op (string): operator (==, !=, ...).
        what (string): name of the statement (tcp, udp, ip, ...)
        value (tuple): array of values (dport -> 22, etc).
    """
    @staticmethod
    def new(op, what, values):
        expr = ui_pb2.Expressions()
        expr.Statement.Op = op
        expr.Statement.Name = what

        for val in values:
            exprValues = ui_pb2.StatementValues()
            exprValues.Key = val[0]
            exprValues.Value = val[1]
            expr.Statement.Values.extend([exprValues])

        return expr

class ExprCt(Enums):
    STATE = "state"
    NEW = "new"
    ESTABLISHED = "established"
    RELATED = "related"
    INVALID = "invalid"
    SET = "set"
    MARK = "mark"

class ExprMeta(Enums):
    SET = "set"
    MARK = "mark"
    L4PROTO = "l4proto"
    SKUID = "skuid"
    SKGID = "skgid"
    PROTOCOL = "protocol"
    PRIORITY = "priority"

class ExprIface(Enums):
    IIFNAME = "iifname"
    OIFNAME = "oifname"

class ExprICMP(Enums):
    ECHO_REQUEST = "echo-request"
    ECHO_REPLY = "echo-reply"
    SOURCE_QUENCH = "source-quench"
    DEST_UNREACHABLE = "destination-unreachable"
    ROUTER_ADVERTISEMENT = "router-advertisement"
    ROUTER_SOLICITATION = "router-solicitation"
    REDIRECT = "redirect"
    TIME_EXCEEDED = "time-exceeded"
    INFO_REQUEST = "info-request"
    INFO_REPLY = "info-reply"
    PARAMETER_PROBLEM = "parameter-problem"
    TIMESTAMP_REQUEST = "timestamp-request"
    TIMESTAMP_REPLY = "timestamp-reply"
    ADDRESS_MASK_REQUEST = "address-mask-request"
    ADDRESS_MASK_REPLY = "address-mask-reply"

    # IPv6
    PACKET_TOO_BIG = "packet-too-big"
    NEIGHBOUR_SOLICITATION = "neighbour-solicitation"
    NEIGHBOUR_ADVERTISEMENT = "neighbour-advertisement"

class ExprICMPRejectCodes(Enums):
    NO_ROUTE = "no-route"
    PROT_UNREACHABLE = "prot-unreachable"
    PORT_UNREACHABLE = "port-unreachable"
    NET_UNREACHABLE = "net-unreachable"
    ADDR_UNREACHABLE = "addr-unreachable"
    HOST_UNREACHABLE = "host-unreachable"
    NET_PROHIBITED = "net-prohibited"
    HOST_PROHIBITED = "host-prohibited"
    ADMIN_PROHIBITED = "admin-prohibited"
    REJECT_ROUTE = "reject-route"
    REJECT_POLICY_FAIL = "policy-fail"

class ExprLog(Enums):
    LOG = "log"
    LEVEL = "level"
    PREFIX = "prefix"

class ExprLogLevels(Enums):
    EMERG = "emerg"
    ALERT = "alert"
    CRIT = "crit"
    ERR = "err"
    WARN = "warn"
    NOTICE = "notice"
    INFO = "info"
    DEBUG = "debug"
    AUDIT = "audit"

class ExprCounter(Enums):
    COUNTER = "counter"
    PACKETS = "packets"
    BYTES = "bytes"
    NAME = "name"

class ExprLimit(Enums):
    OVER = "over"
    LIMIT = "limit"
    UNITS = "units"
    RATE_UNITS = "rate-units"
    TIME_UNITS = "time-units"

class ExprQuota(Enums):
    QUOTA = "quota"
    OVER = "over"
    UNTIL = "until"
    USED = "used"
    UNIT = "unit"
