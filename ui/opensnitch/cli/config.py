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

"""Configuration of opensnitch-cli.

An ini file, read with configparser. The GUI keeps its settings in QSettings,
which needs Qt, so we can't share it. Running without a configuration file at
all is supported: the defaults below are the whole contract.
"""

import configparser
import os

from opensnitch.rule_consts import RuleConsts
from opensnitch.cli import durations

DEFAULT_CONFIG_PATHS = (
    "~/.config/opensnitch/cli.conf",
    "/etc/opensnitch/cli.conf",
)

DEFAULTS = {
    "server": {
        "address": "unix:///tmp/osui.sock",
        "auth_type": "simple",
        "tls_ca_cert": "",
        "tls_cert": "",
        "tls_key": "",
        "max_workers": "10",
        "max_clients": "0",
        "keepalive": "5000",
        "keepalive_timeout": "20000",
        "max_message_length": "4194304",
    },
    "policy": {
        "unreviewed_action": "deny",
        "unreviewed_duration": "1h",
        "default_action": "deny",
        "queue_max": "1000",
    },
    "db": {
        "path": "/var/lib/opensnitch/cli.db",
        "retention_days": "30",
    },
    "log": {
        "level": "info",
        "file": "",
        "store_alerts": "false",
    },
}

ACTIONS = (RuleConsts.ACTION_ALLOW, RuleConsts.ACTION_DENY, RuleConsts.ACTION_REJECT)
AUTH_TYPES = ("simple", "tls-simple", "tls-mutual")
LOG_LEVELS = ("debug", "info", "warning", "error")


class ConfigError(Exception):
    """the configuration file says something we can't act on."""


class Config:
    """typed, validated access to the ini file."""

    def __init__(self, path=None):
        self.path = path
        self._parser = configparser.ConfigParser()
        self._parser.read_dict(DEFAULTS)

        if path is None:
            path = self._find()
        if path is not None:
            if not os.path.isfile(path):
                raise ConfigError("configuration file not found: {0}".format(path))
            self._parser.read(path)
            self.path = path

        self._validate()

    def _find(self):
        for candidate in DEFAULT_CONFIG_PATHS:
            candidate = os.path.expanduser(candidate)
            if os.path.isfile(candidate):
                return candidate
        return None

    def _validate(self):
        """fail at startup rather than half way through a decision.

        A firewall tool that silently ignores a setting it didn't understand is
        worse than one that refuses to start.
        """
        self._choice("policy", "unreviewed_action", ACTIONS)
        self._choice("policy", "default_action", (RuleConsts.ACTION_ALLOW, RuleConsts.ACTION_DENY))
        self._choice("server", "auth_type", AUTH_TYPES)
        self._choice("log", "level", LOG_LEVELS)

        duration = self.get("policy", "unreviewed_duration")
        err = durations.validate(duration)
        if err is not None:
            raise ConfigError("policy.unreviewed_duration: {0}".format(err))
        # "once" rules are dropped by the daemon instead of being stored
        # (daemon/rule/loader.go, addUserRule), so it would ask again for every
        # single connection, and every ask blocks a packet.
        if duration == RuleConsts.DURATION_ONCE:
            raise ConfigError(
                "policy.unreviewed_duration cannot be '{0}': the daemon does not keep "
                "'{0}' rules, so it would ask again for every connection".format(
                    RuleConsts.DURATION_ONCE))

        for section, option in (("server", "max_workers"), ("server", "max_clients"),
                                ("server", "keepalive"), ("server", "keepalive_timeout"),
                                ("server", "max_message_length"),
                                ("policy", "queue_max"), ("db", "retention_days")):
            self.getint(section, option)

        if self.getint("server", "max_workers") < 3:
            # one worker is pinned by the notifications stream of each node, one
            # more is taken while asking, and Ping needs one now and then.
            raise ConfigError("server.max_workers must be at least 3")

    def _choice(self, section, option, valid):
        value = self.get(section, option)
        if value not in valid:
            raise ConfigError("{0}.{1}: '{2}' is not one of {3}".format(
                section, option, value, ", ".join(valid)))
        return value

    def get(self, section, option):
        return self._parser.get(section, option).strip()

    def getint(self, section, option):
        try:
            return int(self.get(section, option))
        except ValueError:
            raise ConfigError("{0}.{1}: '{2}' is not a number".format(
                section, option, self.get(section, option)))

    def getbool(self, section, option):
        try:
            return self._parser.getboolean(section, option)
        except ValueError:
            raise ConfigError("{0}.{1}: '{2}' is not a boolean".format(
                section, option, self.get(section, option)))

    def set(self, section, option, value):
        """override a setting from the command line."""
        self._parser.set(section, option, str(value))
        self._validate()

    def db_path(self):
        return os.path.expanduser(self.get("db", "path"))
