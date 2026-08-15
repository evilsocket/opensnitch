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

"""Rule durations as the daemon understands them, and times for people to read.

Anything that is not one of the three keywords is parsed by the daemon with
Go's time.ParseDuration (daemon/rule/loader.go, scheduleTemporaryRule), which
accepts ns, us, ms, s, m and h, and *not* days or weeks. A duration the daemon
can't parse doesn't fail loudly: the error is discarded and the rule ends up
never expiring, so validate before sending.

opensnitch.utils.duration is the GUI's equivalent, but it needs Qt (it lives
under opensnitch.utils) and it treats "1d" as 60 hours, so it isn't reused here.
"""

import re
import time

from opensnitch.rule_consts import RuleConsts

# the durations the pop-up offers, in the order it offers them
COMMON = (
    RuleConsts.DURATION_30s,
    RuleConsts.DURATION_5m,
    RuleConsts.DURATION_15m,
    RuleConsts.DURATION_30m,
    RuleConsts.DURATION_1h,
    RuleConsts.DURATION_12h,
    RuleConsts.DURATION_UNTIL_RESTART,
    RuleConsts.DURATION_ALWAYS,
)

KEYWORDS = (
    RuleConsts.DURATION_ONCE,
    RuleConsts.DURATION_UNTIL_RESTART,
    RuleConsts.DURATION_ALWAYS,
)

_UNITS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1, "m": 60, "h": 3600}
# same grammar as Go's time.ParseDuration, without the sign
_GO_DURATION = re.compile(r'^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$')
_GO_PART = re.compile(r'([0-9]+(?:\.[0-9]+)?)(ns|us|µs|ms|s|m|h)')


def format_time(timestamp):
    """a stored epoch as local time, for the tables and the review loop."""
    if not timestamp:
        return "?"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


def validate(duration):
    """returns an error string, or None when the daemon will understand it."""
    if duration in KEYWORDS:
        return None
    if duration == "":
        return "empty duration"
    if not _GO_DURATION.match(duration):
        return ("'{0}' is not a valid duration: use one of {1}, or a value like "
                "30s, 5m, 1h30m (days and weeks are not supported by the daemon)".format(
                    duration, ", ".join(KEYWORDS)))
    return None


def to_seconds(duration):
    """seconds a temporary rule will live for, or None if it isn't time based."""
    if duration in KEYWORDS:
        return None
    if validate(duration) is not None:
        return None

    total = 0
    for value, unit in _GO_PART.findall(duration):
        total += float(value) * _UNITS[unit]
    return total


def is_temporary(duration):
    """whether the daemon will schedule the rule for removal.

    Mirrors daemon/rule/loader.go isTemporary(): "once", "until restart" and
    "always" are not scheduled.
    """
    return duration not in KEYWORDS and validate(duration) is None
