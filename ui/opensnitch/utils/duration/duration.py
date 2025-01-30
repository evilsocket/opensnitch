#!/usr/bin/env python3

#   Copyright (C) 2018      Simone Margaritelli
#                 2018      MiWCryptAnalytics
#                 2023      munix9
#                 2023      Wojtek Widomski
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


import re

r = re.compile(r'(\d+)([smhdw]+)')

_second = 1
_minute = 60
_hour   = 60 * _minute
_day    = 60 * _hour
_week   = 60 * _day

_units = {
    's': _second,
    'm': _minute,
    'h': _hour,
    'd': _day,
    'w': _week
}

def to_seconds(dur_str):
    """converts a Golang duration string to seconds:
        "20s" -> 20 seconds
        "2m"  -> 120 seconds
        ...
    """
    secs = 0
    try:
        finds = r.findall(dur_str)
        for d in finds:
            try:
                unit = _units[d[1]]
                secs += (unit * int(d[0]))
            except:
                print("duration.to_seconds(): invalid unit:", d)

        return secs
    except:
        return secs
