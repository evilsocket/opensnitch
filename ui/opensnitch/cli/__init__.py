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

"""Headless client for servers without a graphical environment.

opensnitch-cli serve answers the daemon's AskRule requests without a human in
the loop, and records every connection it hasn't seen before in a review queue.
opensnitch-cli review goes through that queue afterwards.

Nothing in this package may import PyQt: it's meant to run on machines where Qt
is not installed. ui/tests/cli/test_no_qt.py enforces it.
"""
