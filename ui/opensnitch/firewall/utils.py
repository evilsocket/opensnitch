
from .enums import *

class Utils():

    @staticmethod
    def isExprPort(value):
        """Return true if the value is valid for a port based rule:
            nft add rule ... tcp dport 22 accept
        """
        return value == Statements.TCP.value or \
                value == Statements.UDP.value or \
                value == Statements.UDPLITE.value or \
                value == Statements.SCTP.value or \
                value == Statements.DCCP.value
