from opensnitch.utils import Enums
from opensnitch.config import Config

class Verdicts(Enums):
    EMPTY = ""
    ACCEPT = Config.ACTION_ACCEPT
    DROP = Config.ACTION_DROP
    REJECT = Config.ACTION_REJECT
    RETURN = Config.ACTION_RETURN
    QUEUE = Config.ACTION_QUEUE
    DNAT = Config.ACTION_DNAT
    SNAT = Config.ACTION_SNAT
    REDIRECT = Config.ACTION_REDIRECT
    TPROXY = Config.ACTION_TPROXY
    #MASQUERADE = Config.ACTION_MASQUERADE
    #LOG = Config.ACTION_LOG
    STOP = Config.ACTION_STOP



class Policy(Enums):
    ACCEPT = "accept"
    DROP = "drop"

class Table(Enums):
    FILTER = "filter"
    MANGLE = "mangle"
    NAT = "nat"

class Hooks(Enums):
    INPUT  ="input"
    OUTPUT  ="output"
    FORWARD = "forward"
    PREROUTING = "prerouting"
    POSTROUTING = "postrouting"

class PortProtocols(Enums):
    TCPUDP = "tcp,udp"
    TCP = "tcp"
    UDP = "udp"
    UDPLITE = "udplite"
    SCTP = "sctp"
    DCCP = "dccp"

class Protocols(Enums):
    TCP = "tcp"
    UDP = "udp"
    UDPLITE = "udplite"
    SCTP = "sctp"
    DCCP = "dccp"
    ICMP = "icmp"
    ICMPv6 = "icmpv6"
    AH = "ah"
    ETHERNET = "ethernet"
    GREP = "gre"
    IP = "ip"
    IPIP = "ipip"
    L2TP = "l2tp"
    COMP = "comp"
    IGMP = "igmp"
    ESP = "esp"
    RAW = "raw"
    ENCAP = "encap"

class Family(Enums):
    INET = "inet"
    IPv4 = "ip"
    IPv6 = "ip6"

class ChainType(Enums):
    FILTER = "filter"
    MANGLE = "mangle"
    ROUTE = "route"
    SNAT = "natsource"
    DNAT = "natdest"

class Operator(Enums):
    EQUAL = "=="
    NOT_EQUAL = "!="
    GT_THAN = ">="
    GT = ">"
    LT_THAN = "<="
    LT = "<"

class TimeUnits(Enums):
    SECOND = "second"
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"

class RateUnits(Enums):
    BYTES = "bytes"
    KBYTES = "kbytes"
    MBYTES = "mbytes"
    GBYTES = "gbytes"

class Statements(Enums):
    """Enum of known (allowed) statements:
        [tcp,udp,ip] ...
    """
    # we may need in the future:
    # ANY = tcp,udp,udplite,sctp,dccp
    TCPUDP = "tcp,udp"
    TCP = "tcp"
    UDP = "udp"
    UDPLITE = "udplite"
    SCTP = "sctp"
    DCCP = "dccp"
    ICMP = "icmp"
    ICMPv6 = "icmpv6"

    SPORT = "sport"
    DPORT = "dport"
    DADDR = "daddr"
    SADDR = "saddr"

    IP = "ip"
    IP6 = "ip6"
    IIFNAME = "iifname"
    OIFNAME = "oifname"
    CT = "ct"
    META = "meta"
    COUNTER = "counter"
    NAME = "name"
    LOG = "log"
    QUOTA = "quota"
    LIMIT = "limit"
