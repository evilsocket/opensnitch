
from google.protobuf import __version__ as protobuf_version
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

    @staticmethod
    def isProtobufSupported():
        """
        The protobuf operations append() and insert() were introduced on 3.8.0 version.
        """
        vparts = protobuf_version.split(".")
        return int(vparts[0]) >= 3 and int(vparts[1]) >= 8
