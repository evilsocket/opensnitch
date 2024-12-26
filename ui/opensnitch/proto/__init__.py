#   Copyright (C) 2018      Simone Margaritelli
#                 2019-2025 Gustavo Iñiguez Goia
#
#   This file is part of OpenSnitch.
#
#   OpenSnitch is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   OpenSnitch is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with OpenSnitch.  If not, see <http://www.gnu.org/licenses/>.

from packaging.version import Version
import importlib
from opensnitch.utils import Versions

# Protobuffers compiled with protobuf < 3.20.0 are incompatible with
# protobuf >= 4.0.0
# https://github.com/evilsocket/opensnitch/wiki/GUI-known-problems#gui-does-not-show-up
#
# In order to solve this issue, we provide several protobuffers:
# proto.ui_pb2* for protobuf >= 4.0.0
# proto.pre3200.ui_pb2* for protobuf >= 3.6.0 and < 3.20.0
#
# To avoid import errors, each protobuffer must be placed in its own directory,
# and the name of the protobuffer files must be named with the syntax
# <prefix>_pb2.py/<prefix>_pb2_grpc.py:
#  ui_pb2.py and ui_pb2_grpc.py

default_pb = "opensnitch.proto.ui_pb2"
default_grpc = "opensnitch.proto.ui_pb2_grpc"
old_pb = "opensnitch.proto.pre3200.ui_pb2"
old_grpc = "opensnitch.proto.pre3200.ui_pb2_grpc"

def import_():
    """load the protobuffer needed based on the grpc and protobuffer version
    installed in the system.
    """
    try:
        gui_version, grpc_version, proto_version = Versions.get()
        proto_ver = default_pb
        grpc_ver = default_grpc

        if Version(proto_version) < Version("3.20.0"):
            proto_ver = old_pb
            grpc_ver = old_grpc

        return importlib.import_module(proto_ver), importlib.import_module(grpc_ver)
    except Exception as e:
        print("error importing protobuffer: ", repr(e))
        return importlib.import_module(default_pb, default_grpc)
