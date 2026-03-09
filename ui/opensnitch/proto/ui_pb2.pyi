from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Action(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NONE: _ClassVar[Action]
    ENABLE_INTERCEPTION: _ClassVar[Action]
    DISABLE_INTERCEPTION: _ClassVar[Action]
    ENABLE_FIREWALL: _ClassVar[Action]
    DISABLE_FIREWALL: _ClassVar[Action]
    RELOAD_FW_RULES: _ClassVar[Action]
    CHANGE_CONFIG: _ClassVar[Action]
    ENABLE_RULE: _ClassVar[Action]
    DISABLE_RULE: _ClassVar[Action]
    DELETE_RULE: _ClassVar[Action]
    CHANGE_RULE: _ClassVar[Action]
    LOG_LEVEL: _ClassVar[Action]
    STOP: _ClassVar[Action]
    TASK_START: _ClassVar[Action]
    TASK_STOP: _ClassVar[Action]

class NotificationReplyCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OK: _ClassVar[NotificationReplyCode]
    ERROR: _ClassVar[NotificationReplyCode]
NONE: Action
ENABLE_INTERCEPTION: Action
DISABLE_INTERCEPTION: Action
ENABLE_FIREWALL: Action
DISABLE_FIREWALL: Action
RELOAD_FW_RULES: Action
CHANGE_CONFIG: Action
ENABLE_RULE: Action
DISABLE_RULE: Action
DELETE_RULE: Action
CHANGE_RULE: Action
LOG_LEVEL: Action
STOP: Action
TASK_START: Action
TASK_STOP: Action
OK: NotificationReplyCode
ERROR: NotificationReplyCode

class Alert(_message.Message):
    __slots__ = ()
    class Priority(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        LOW: _ClassVar[Alert.Priority]
        MEDIUM: _ClassVar[Alert.Priority]
        HIGH: _ClassVar[Alert.Priority]
    LOW: Alert.Priority
    MEDIUM: Alert.Priority
    HIGH: Alert.Priority
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ERROR: _ClassVar[Alert.Type]
        WARNING: _ClassVar[Alert.Type]
        INFO: _ClassVar[Alert.Type]
    ERROR: Alert.Type
    WARNING: Alert.Type
    INFO: Alert.Type
    class Action(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NONE: _ClassVar[Alert.Action]
        SHOW_ALERT: _ClassVar[Alert.Action]
        SAVE_TO_DB: _ClassVar[Alert.Action]
    NONE: Alert.Action
    SHOW_ALERT: Alert.Action
    SAVE_TO_DB: Alert.Action
    class What(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        GENERIC: _ClassVar[Alert.What]
        PROC_MONITOR: _ClassVar[Alert.What]
        FIREWALL: _ClassVar[Alert.What]
        CONNECTION: _ClassVar[Alert.What]
        RULE: _ClassVar[Alert.What]
        NETLINK: _ClassVar[Alert.What]
        KERNEL_EVENT: _ClassVar[Alert.What]
    GENERIC: Alert.What
    PROC_MONITOR: Alert.What
    FIREWALL: Alert.What
    CONNECTION: Alert.What
    RULE: Alert.What
    NETLINK: Alert.What
    KERNEL_EVENT: Alert.What
    ID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    PRIORITY_FIELD_NUMBER: _ClassVar[int]
    WHAT_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    PROC_FIELD_NUMBER: _ClassVar[int]
    CONN_FIELD_NUMBER: _ClassVar[int]
    RULE_FIELD_NUMBER: _ClassVar[int]
    FWRULE_FIELD_NUMBER: _ClassVar[int]
    id: int
    type: Alert.Type
    action: Alert.Action
    priority: Alert.Priority
    what: Alert.What
    text: str
    proc: Process
    conn: Connection
    rule: Rule
    fwrule: FwRule
    def __init__(self, id: _Optional[int] = ..., type: _Optional[_Union[Alert.Type, str]] = ..., action: _Optional[_Union[Alert.Action, str]] = ..., priority: _Optional[_Union[Alert.Priority, str]] = ..., what: _Optional[_Union[Alert.What, str]] = ..., text: _Optional[str] = ..., proc: _Optional[_Union[Process, _Mapping]] = ..., conn: _Optional[_Union[Connection, _Mapping]] = ..., rule: _Optional[_Union[Rule, _Mapping]] = ..., fwrule: _Optional[_Union[FwRule, _Mapping]] = ...) -> None: ...

class MsgResponse(_message.Message):
    __slots__ = ()
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class Event(_message.Message):
    __slots__ = ()
    TIME_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_FIELD_NUMBER: _ClassVar[int]
    RULE_FIELD_NUMBER: _ClassVar[int]
    UNIXNANO_FIELD_NUMBER: _ClassVar[int]
    time: str
    connection: Connection
    rule: Rule
    unixnano: int
    def __init__(self, time: _Optional[str] = ..., connection: _Optional[_Union[Connection, _Mapping]] = ..., rule: _Optional[_Union[Rule, _Mapping]] = ..., unixnano: _Optional[int] = ...) -> None: ...

class Statistics(_message.Message):
    __slots__ = ()
    class ByProtoEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    class ByAddressEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    class ByHostEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    class ByPortEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    class ByUidEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    class ByExecutableEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    DAEMON_VERSION_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    UPTIME_FIELD_NUMBER: _ClassVar[int]
    DNS_RESPONSES_FIELD_NUMBER: _ClassVar[int]
    CONNECTIONS_FIELD_NUMBER: _ClassVar[int]
    IGNORED_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_FIELD_NUMBER: _ClassVar[int]
    DROPPED_FIELD_NUMBER: _ClassVar[int]
    RULE_HITS_FIELD_NUMBER: _ClassVar[int]
    RULE_MISSES_FIELD_NUMBER: _ClassVar[int]
    BY_PROTO_FIELD_NUMBER: _ClassVar[int]
    BY_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    BY_HOST_FIELD_NUMBER: _ClassVar[int]
    BY_PORT_FIELD_NUMBER: _ClassVar[int]
    BY_UID_FIELD_NUMBER: _ClassVar[int]
    BY_EXECUTABLE_FIELD_NUMBER: _ClassVar[int]
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    daemon_version: str
    rules: int
    uptime: int
    dns_responses: int
    connections: int
    ignored: int
    accepted: int
    dropped: int
    rule_hits: int
    rule_misses: int
    by_proto: _containers.ScalarMap[str, int]
    by_address: _containers.ScalarMap[str, int]
    by_host: _containers.ScalarMap[str, int]
    by_port: _containers.ScalarMap[str, int]
    by_uid: _containers.ScalarMap[str, int]
    by_executable: _containers.ScalarMap[str, int]
    events: _containers.RepeatedCompositeFieldContainer[Event]
    def __init__(self, daemon_version: _Optional[str] = ..., rules: _Optional[int] = ..., uptime: _Optional[int] = ..., dns_responses: _Optional[int] = ..., connections: _Optional[int] = ..., ignored: _Optional[int] = ..., accepted: _Optional[int] = ..., dropped: _Optional[int] = ..., rule_hits: _Optional[int] = ..., rule_misses: _Optional[int] = ..., by_proto: _Optional[_Mapping[str, int]] = ..., by_address: _Optional[_Mapping[str, int]] = ..., by_host: _Optional[_Mapping[str, int]] = ..., by_port: _Optional[_Mapping[str, int]] = ..., by_uid: _Optional[_Mapping[str, int]] = ..., by_executable: _Optional[_Mapping[str, int]] = ..., events: _Optional[_Iterable[_Union[Event, _Mapping]]] = ...) -> None: ...

class PingRequest(_message.Message):
    __slots__ = ()
    ID_FIELD_NUMBER: _ClassVar[int]
    STATS_FIELD_NUMBER: _ClassVar[int]
    id: int
    stats: Statistics
    def __init__(self, id: _Optional[int] = ..., stats: _Optional[_Union[Statistics, _Mapping]] = ...) -> None: ...

class PingReply(_message.Message):
    __slots__ = ()
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class StringInt(_message.Message):
    __slots__ = ()
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: int
    def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...

class Process(_message.Message):
    __slots__ = ()
    class EnvEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class ChecksumsEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PID_FIELD_NUMBER: _ClassVar[int]
    PPID_FIELD_NUMBER: _ClassVar[int]
    UID_FIELD_NUMBER: _ClassVar[int]
    COMM_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    ARGS_FIELD_NUMBER: _ClassVar[int]
    ENV_FIELD_NUMBER: _ClassVar[int]
    CWD_FIELD_NUMBER: _ClassVar[int]
    CHECKSUMS_FIELD_NUMBER: _ClassVar[int]
    IO_READS_FIELD_NUMBER: _ClassVar[int]
    IO_WRITES_FIELD_NUMBER: _ClassVar[int]
    NET_READS_FIELD_NUMBER: _ClassVar[int]
    NET_WRITES_FIELD_NUMBER: _ClassVar[int]
    PROCESS_TREE_FIELD_NUMBER: _ClassVar[int]
    pid: int
    ppid: int
    uid: int
    comm: str
    path: str
    args: _containers.RepeatedScalarFieldContainer[str]
    env: _containers.ScalarMap[str, str]
    cwd: str
    checksums: _containers.ScalarMap[str, str]
    io_reads: int
    io_writes: int
    net_reads: int
    net_writes: int
    process_tree: _containers.RepeatedCompositeFieldContainer[StringInt]
    def __init__(self, pid: _Optional[int] = ..., ppid: _Optional[int] = ..., uid: _Optional[int] = ..., comm: _Optional[str] = ..., path: _Optional[str] = ..., args: _Optional[_Iterable[str]] = ..., env: _Optional[_Mapping[str, str]] = ..., cwd: _Optional[str] = ..., checksums: _Optional[_Mapping[str, str]] = ..., io_reads: _Optional[int] = ..., io_writes: _Optional[int] = ..., net_reads: _Optional[int] = ..., net_writes: _Optional[int] = ..., process_tree: _Optional[_Iterable[_Union[StringInt, _Mapping]]] = ...) -> None: ...

class Connection(_message.Message):
    __slots__ = ()
    class ProcessEnvEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class ProcessChecksumsEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    SRC_IP_FIELD_NUMBER: _ClassVar[int]
    SRC_PORT_FIELD_NUMBER: _ClassVar[int]
    DST_IP_FIELD_NUMBER: _ClassVar[int]
    DST_HOST_FIELD_NUMBER: _ClassVar[int]
    DST_PORT_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    PROCESS_ID_FIELD_NUMBER: _ClassVar[int]
    PROCESS_PATH_FIELD_NUMBER: _ClassVar[int]
    PROCESS_CWD_FIELD_NUMBER: _ClassVar[int]
    PROCESS_ARGS_FIELD_NUMBER: _ClassVar[int]
    PROCESS_ENV_FIELD_NUMBER: _ClassVar[int]
    PROCESS_CHECKSUMS_FIELD_NUMBER: _ClassVar[int]
    PROCESS_TREE_FIELD_NUMBER: _ClassVar[int]
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_host: str
    dst_port: int
    user_id: int
    process_id: int
    process_path: str
    process_cwd: str
    process_args: _containers.RepeatedScalarFieldContainer[str]
    process_env: _containers.ScalarMap[str, str]
    process_checksums: _containers.ScalarMap[str, str]
    process_tree: _containers.RepeatedCompositeFieldContainer[StringInt]
    def __init__(self, protocol: _Optional[str] = ..., src_ip: _Optional[str] = ..., src_port: _Optional[int] = ..., dst_ip: _Optional[str] = ..., dst_host: _Optional[str] = ..., dst_port: _Optional[int] = ..., user_id: _Optional[int] = ..., process_id: _Optional[int] = ..., process_path: _Optional[str] = ..., process_cwd: _Optional[str] = ..., process_args: _Optional[_Iterable[str]] = ..., process_env: _Optional[_Mapping[str, str]] = ..., process_checksums: _Optional[_Mapping[str, str]] = ..., process_tree: _Optional[_Iterable[_Union[StringInt, _Mapping]]] = ...) -> None: ...

class Operator(_message.Message):
    __slots__ = ()
    TYPE_FIELD_NUMBER: _ClassVar[int]
    OPERAND_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    SENSITIVE_FIELD_NUMBER: _ClassVar[int]
    LIST_FIELD_NUMBER: _ClassVar[int]
    type: str
    operand: str
    data: str
    sensitive: bool
    list: _containers.RepeatedCompositeFieldContainer[Operator]
    def __init__(self, type: _Optional[str] = ..., operand: _Optional[str] = ..., data: _Optional[str] = ..., sensitive: _Optional[bool] = ..., list: _Optional[_Iterable[_Union[Operator, _Mapping]]] = ...) -> None: ...

class Rule(_message.Message):
    __slots__ = ()
    CREATED_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    PRECEDENCE_FIELD_NUMBER: _ClassVar[int]
    NOLOG_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    DURATION_FIELD_NUMBER: _ClassVar[int]
    OPERATOR_FIELD_NUMBER: _ClassVar[int]
    created: int
    name: str
    description: str
    enabled: bool
    precedence: bool
    nolog: bool
    action: str
    duration: str
    operator: Operator
    def __init__(self, created: _Optional[int] = ..., name: _Optional[str] = ..., description: _Optional[str] = ..., enabled: _Optional[bool] = ..., precedence: _Optional[bool] = ..., nolog: _Optional[bool] = ..., action: _Optional[str] = ..., duration: _Optional[str] = ..., operator: _Optional[_Union[Operator, _Mapping]] = ...) -> None: ...

class StatementValues(_message.Message):
    __slots__ = ()
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    Key: str
    Value: str
    def __init__(self, Key: _Optional[str] = ..., Value: _Optional[str] = ...) -> None: ...

class Statement(_message.Message):
    __slots__ = ()
    OP_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    Op: str
    Name: str
    Values: _containers.RepeatedCompositeFieldContainer[StatementValues]
    def __init__(self, Op: _Optional[str] = ..., Name: _Optional[str] = ..., Values: _Optional[_Iterable[_Union[StatementValues, _Mapping]]] = ...) -> None: ...

class Expressions(_message.Message):
    __slots__ = ()
    STATEMENT_FIELD_NUMBER: _ClassVar[int]
    Statement: Statement
    def __init__(self, Statement: _Optional[_Union[Statement, _Mapping]] = ...) -> None: ...

class FwRule(_message.Message):
    __slots__ = ()
    TABLE_FIELD_NUMBER: _ClassVar[int]
    CHAIN_FIELD_NUMBER: _ClassVar[int]
    UUID_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    POSITION_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    PARAMETERS_FIELD_NUMBER: _ClassVar[int]
    EXPRESSIONS_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    TARGETPARAMETERS_FIELD_NUMBER: _ClassVar[int]
    Table: str
    Chain: str
    UUID: str
    Enabled: bool
    Position: int
    Description: str
    Parameters: str
    Expressions: _containers.RepeatedCompositeFieldContainer[Expressions]
    Target: str
    TargetParameters: str
    def __init__(self, Table: _Optional[str] = ..., Chain: _Optional[str] = ..., UUID: _Optional[str] = ..., Enabled: _Optional[bool] = ..., Position: _Optional[int] = ..., Description: _Optional[str] = ..., Parameters: _Optional[str] = ..., Expressions: _Optional[_Iterable[_Union[Expressions, _Mapping]]] = ..., Target: _Optional[str] = ..., TargetParameters: _Optional[str] = ...) -> None: ...

class FwChain(_message.Message):
    __slots__ = ()
    NAME_FIELD_NUMBER: _ClassVar[int]
    TABLE_FIELD_NUMBER: _ClassVar[int]
    FAMILY_FIELD_NUMBER: _ClassVar[int]
    PRIORITY_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    HOOK_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    Name: str
    Table: str
    Family: str
    Priority: str
    Type: str
    Hook: str
    Policy: str
    Rules: _containers.RepeatedCompositeFieldContainer[FwRule]
    def __init__(self, Name: _Optional[str] = ..., Table: _Optional[str] = ..., Family: _Optional[str] = ..., Priority: _Optional[str] = ..., Type: _Optional[str] = ..., Hook: _Optional[str] = ..., Policy: _Optional[str] = ..., Rules: _Optional[_Iterable[_Union[FwRule, _Mapping]]] = ...) -> None: ...

class FwChains(_message.Message):
    __slots__ = ()
    RULE_FIELD_NUMBER: _ClassVar[int]
    CHAINS_FIELD_NUMBER: _ClassVar[int]
    Rule: FwRule
    Chains: _containers.RepeatedCompositeFieldContainer[FwChain]
    def __init__(self, Rule: _Optional[_Union[FwRule, _Mapping]] = ..., Chains: _Optional[_Iterable[_Union[FwChain, _Mapping]]] = ...) -> None: ...

class SysFirewall(_message.Message):
    __slots__ = ()
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    SYSTEMRULES_FIELD_NUMBER: _ClassVar[int]
    Enabled: bool
    Version: int
    SystemRules: _containers.RepeatedCompositeFieldContainer[FwChains]
    def __init__(self, Enabled: _Optional[bool] = ..., Version: _Optional[int] = ..., SystemRules: _Optional[_Iterable[_Union[FwChains, _Mapping]]] = ...) -> None: ...

class ClientConfig(_message.Message):
    __slots__ = ()
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    ISFIREWALLRUNNING_FIELD_NUMBER: _ClassVar[int]
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    LOGLEVEL_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    SYSTEMFIREWALL_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    version: str
    isFirewallRunning: bool
    config: str
    logLevel: int
    rules: _containers.RepeatedCompositeFieldContainer[Rule]
    systemFirewall: SysFirewall
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ..., version: _Optional[str] = ..., isFirewallRunning: _Optional[bool] = ..., config: _Optional[str] = ..., logLevel: _Optional[int] = ..., rules: _Optional[_Iterable[_Union[Rule, _Mapping]]] = ..., systemFirewall: _Optional[_Union[SysFirewall, _Mapping]] = ...) -> None: ...

class Notification(_message.Message):
    __slots__ = ()
    ID_FIELD_NUMBER: _ClassVar[int]
    CLIENTNAME_FIELD_NUMBER: _ClassVar[int]
    SERVERNAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    SYSFIREWALL_FIELD_NUMBER: _ClassVar[int]
    id: int
    clientName: str
    serverName: str
    type: Action
    data: str
    rules: _containers.RepeatedCompositeFieldContainer[Rule]
    sysFirewall: SysFirewall
    def __init__(self, id: _Optional[int] = ..., clientName: _Optional[str] = ..., serverName: _Optional[str] = ..., type: _Optional[_Union[Action, str]] = ..., data: _Optional[str] = ..., rules: _Optional[_Iterable[_Union[Rule, _Mapping]]] = ..., sysFirewall: _Optional[_Union[SysFirewall, _Mapping]] = ...) -> None: ...

class NotificationReply(_message.Message):
    __slots__ = ()
    ID_FIELD_NUMBER: _ClassVar[int]
    CODE_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    id: int
    code: NotificationReplyCode
    data: str
    def __init__(self, id: _Optional[int] = ..., code: _Optional[_Union[NotificationReplyCode, str]] = ..., data: _Optional[str] = ...) -> None: ...
