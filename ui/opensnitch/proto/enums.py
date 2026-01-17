from opensnitch.utils import Enums

# String name of the protobuffer fields.
# Used for advanced search or templates substitutions.

class ConnFields(Enums):
    Time = "conn.time"
    SrcPort = "conn.srcport"
    SrcIP = "conn.srcip"
    DstHost = "conn.dsthost"
    DstPort = "conn.dstport"
    DstIP = "conn.dstip"
    PID = "conn.pid"
    UID = "conn.uid"
    Rule = "conn.rule"
    Process = "conn.process"
    ProcCWD = "conn.process_cwd"
    Cmdline = "conn.process_args"
    Proto = "conn.proto"
    Action = "conn.action"
    Node = "conn.node"

class RuleFields(Enums):
    Action = "rule.action"
    Name = "rule.name"
    Time = "rule.time"

class NodeFields(Enums):
    Addr = "node.addr"
    Hostname = "node.hostname"
    ID = "node.id"
