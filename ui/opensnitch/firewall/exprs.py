
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
            expr.Statement.Values.append(exprValues)

        return expr

class ExprCt(Enums):
    STATE = "state"
    NEW = "new"
    ESTABLISHED = "established"
    RELATED = "related"

class ExprIface(Enums):
    IIFNAME = "iifname"
    OIFNAME = "oifname"

class ExprLog(Enums):
    LOG = "log"
