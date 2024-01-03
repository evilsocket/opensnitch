
class ConnFields():
    Time = 0
    Node = 1
    Action = 2
    Protocol = 3
    SrcIP = 4
    SrcPort = 5
    DstIP = 6
    DstHost = 7
    DstPort = 8
    UID = 9
    PID = 10
    Process = 11
    Cmdline = 12
    CWD = 13
    Rule = 14

class RuleFields():
    """These fields must be in the order defined in the DB"""
    Time = 0
    Node = 1
    Name = 2
    Enabled = 3
    Precedence = 4
    Action = 5
    Duration = 6
    OpType = 7
    OpSensitive = 8
    OpOperand = 9
    OpData = 10
    Description = 11
    NoLog = 12
    Created = 13

class AlertFields():
    Time = 0
    Node = 1
    Type = 2
    Action = 3
    Priority = 4
    What = 5
    Body = 6
    Status = 7
