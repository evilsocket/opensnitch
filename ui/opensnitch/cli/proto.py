#   Copyright (C) 2026 The OpenSnitch Authors
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

"""The protobuffers, picked according to the installed protobuf version.

opensnitch.proto.import_() chooses between the current protobuffers and the ones
built for protobuf < 3.20. Importing it from a single place keeps that choice
consistent across the package, and keeps the 'import grpc' cost out of the
commands that don't talk to a daemon.
"""

from opensnitch import proto

ui_pb2, ui_pb2_grpc = proto.import_()
