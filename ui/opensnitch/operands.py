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

"""Builds rule operators out of a connection.

This is the logic behind the "apply to" selector of the pop-up dialog, with
the Qt parts left out, so that it can be shared with components that run
without a graphical environment (opensnitch-cli).

Every builder returns a (type, operand, data) tuple, ready to be assigned to a
ui_pb2.Operator. The daemon side counterpart is daemon/rule/operator.go
"""

import ipaddress
import os
import re

from opensnitch.rule_consts import RuleConsts


def _get_network_alias(dst_ip):
    """network aliases live under opensnitch.utils, which needs Qt.

    Import it only when it's available, so that this module keeps working on
    systems without a graphical environment.
    """
    try:
        from opensnitch.utils.network_aliases import NetworkAliases
        return NetworkAliases.get_alias(dst_ip)
    except ImportError:
        return None

# Identifiers of the fields a connection can be matched on. They are stored as
# the userData of the pop-up combo boxes, so don't translate them and don't
# change their values.
FIELD_REGEX_HOST    = "regex_host"
FIELD_REGEX_IP      = "regex_ip"
FIELD_PROC_PATH     = "process_path"
FIELD_PROC_ARGS     = "process_args"
FIELD_PROC_ID       = "process_id"
FIELD_USER_ID       = "user_id"
FIELD_DST_IP        = "dst_ip"
FIELD_DST_PORT      = "dst_port"
FIELD_DST_NETWORK   = "dst_network"
FIELD_DST_HOST      = "simple_host"
FIELD_APPIMAGE      = "appimage_path"
FIELD_SNAP          = "snap_path"

APPIMAGE_PREFIX = "/tmp/.mount_"
SNAP_PREFIX = "/snap"

# Constructs that Python's re accepts but Go's RE2 engine does not. A rule
# using any of them is silently rejected by the daemon, so warn about it before
# sending it. @doc: https://github.com/google/re2/wiki/Syntax
RE2_UNSUPPORTED = (
    (r'(?=', "lookahead"),
    (r'(?!', "negative lookahead"),
    (r'(?<=', "lookbehind"),
    (r'(?<!', "negative lookbehind"),
    (r'(?>', "atomic group"),
)
_BACKREF_RE = re.compile(r'\\[1-9]')


def from_process_path(process_path):
    return RuleConsts.RULE_TYPE_SIMPLE, RuleConsts.OPERAND_PROCESS_PATH, process_path

def from_process_command(process_args, process_path):
    """matches on the whole command line.

    Falls back to the executable path when the arguments are not available,
    which is what the pop-up does.
    """
    if len(process_args) == 0 or process_args[0] == "":
        return from_process_path(process_path)
    return RuleConsts.RULE_TYPE_SIMPLE, RuleConsts.OPERAND_PROCESS_COMMAND, ' '.join(process_args)

def from_process_id(process_id):
    return RuleConsts.RULE_TYPE_SIMPLE, RuleConsts.OPERAND_PROCESS_ID, "{0}".format(process_id)

def from_user_id(user_id):
    return RuleConsts.RULE_TYPE_SIMPLE, RuleConsts.OPERAND_USER_ID, "{0}".format(user_id)

def from_dest_port(dst_port):
    return RuleConsts.RULE_TYPE_SIMPLE, RuleConsts.OPERAND_DEST_PORT, "{0}".format(dst_port)

def from_dest_ip(dst_ip):
    return RuleConsts.RULE_TYPE_SIMPLE, RuleConsts.OPERAND_DEST_IP, dst_ip

def from_dest_host(dst_host):
    return RuleConsts.RULE_TYPE_SIMPLE, RuleConsts.OPERAND_DEST_HOST, dst_host

def from_dest_network(network):
    """network is a CIDR or a network alias, for example 192.168.1.0/24"""
    return RuleConsts.RULE_TYPE_NETWORK, RuleConsts.OPERAND_DEST_NETWORK, network

def from_dest_host_wildcard(domain):
    """matches a domain and all of its subdomains.

    "yahoo.com" -> ^(|.*\\.)yahoo\\.com$
    """
    escaped = r'\.'.join(domain.split('.'))
    return RuleConsts.RULE_TYPE_REGEXP, RuleConsts.OPERAND_DEST_HOST, r'^(|.*\.)%s$' % escaped

def from_dest_ip_wildcard(prefix):
    """matches a range of addresses by prefix.

    "192.168.*" -> 192\\.168\\..*
    """
    return RuleConsts.RULE_TYPE_REGEXP, RuleConsts.OPERAND_DEST_IP, \
        "%s" % r'\.'.join(prefix.split('.')).replace("*", ".*")

def from_appimage_path(process_path):
    """appimages are mounted on /tmp/.mount_<random>, which changes on every run.

    Usually appimages add 6 random characters after the prefix, but some of them
    do not follow this rule (Eden appimage for example, #1377).
    """
    appimage_bin = os.path.basename(process_path)
    appimage_path = os.path.dirname(process_path).replace('.', r'\.')
    appimage_path = appimage_path[0:len(APPIMAGE_PREFIX)+7]
    return RuleConsts.RULE_TYPE_REGEXP, RuleConsts.OPERAND_PROCESS_PATH, \
        r'^{0}[0-9A-Za-z]+\/.*{1}$'.format(appimage_path, appimage_bin)

def from_snap_path(process_path):
    """snap paths contain a revision number, which changes after every update."""
    snap_parts = process_path.split('/')
    snap_prefix = snap_parts[1]
    app = snap_parts[2]
    app_path = r'\/'.join(snap_parts[4:])
    return RuleConsts.RULE_TYPE_REGEXP, RuleConsts.OPERAND_PROCESS_PATH, \
        r'^\/{0}\/{1}\/[0-9]+\/{2}$'.format(snap_prefix, app, app_path)


def get_operator(field, value, con):
    """returns the (type, operand, data) tuple for the given field.

    value is the already normalized value of the field: no display prefixes and
    no leading "*." for the wildcard fields. It's ignored by the fields that are
    fully determined by the connection.
    """
    if field == FIELD_PROC_PATH:
        return from_process_path(con.process_path)
    elif field == FIELD_PROC_ARGS:
        return from_process_command(con.process_args, con.process_path)
    elif field == FIELD_PROC_ID:
        return from_process_id(con.process_id)
    elif field == FIELD_USER_ID:
        return from_user_id(con.user_id)
    elif field == FIELD_DST_PORT:
        return from_dest_port(con.dst_port)
    elif field == FIELD_DST_IP:
        return from_dest_ip(con.dst_ip)
    elif field == FIELD_DST_HOST:
        return from_dest_host(value)
    elif field == FIELD_DST_NETWORK:
        return from_dest_network(value)
    elif field == FIELD_REGEX_HOST:
        return from_dest_host_wildcard(value)
    elif field == FIELD_REGEX_IP:
        return from_dest_ip_wildcard(value)
    elif field == FIELD_APPIMAGE:
        return from_appimage_path(con.process_path)
    elif field == FIELD_SNAP:
        return from_snap_path(con.process_path)

    return None, None, None


def dest_ip_wildcards(dst_ip):
    """progressively wider address prefixes: 192.*, 192.168.*, ..."""
    prefixes = []
    parts = dst_ip.split('.')
    for i in range(1, len(parts)):
        prefixes.append("{0}.*".format('.'.join(parts[:i])))
    return prefixes

def dest_host_wildcards(dst_host):
    """parent domains of a host: for a.b.example.com -> b.example.com, example.com"""
    domains = []
    parts = dst_host.split('.')[1:]
    for i in range(0, len(parts) - 1):
        domains.append('.'.join(parts[i:]))
    return domains

def dest_networks(dst_ip):
    """the networks the address belongs to, widest last, plus any matching alias."""
    networks = []
    alias = _get_network_alias(dst_ip)
    if alias:
        networks.append(alias)
    if type(ipaddress.ip_address(dst_ip)) == ipaddress.IPv4Address:
        masks = ("/24", "/16", "/8")
    else:
        masks = ("/64", "/128")
    for mask in masks:
        networks.append("{0}".format(ipaddress.ip_network(dst_ip + mask, strict=False)))
    return networks


def candidates(con):
    """everything a connection can reasonably be matched on, best guess first.

    Same set the pop-up offers in its "apply to" combo, as a plain list so that
    it can be printed in a terminal. Each entry is a dict with a label to show
    and the (type, operand, data) to put in the rule.
    """
    found = []

    def add(label, triple):
        op_type, operand, data = triple
        if data is None or data == "":
            return
        found.append({"label": label, "type": op_type, "operand": operand, "data": data})

    if con.process_path != "":
        if con.process_path.startswith(APPIMAGE_PREFIX):
            add("this appimage, whatever it is mounted on",
                from_appimage_path(con.process_path))
        elif con.process_path.startswith(SNAP_PREFIX):
            add("this snap, whatever its revision", from_snap_path(con.process_path))
        add("this executable", from_process_path(con.process_path))

    if len(con.process_args) > 0 and con.process_args[0] != "":
        add("this command line", from_process_command(con.process_args, con.process_path))

    checksums = dict(getattr(con, "process_checksums", None) or {})
    md5 = checksums.get(RuleConsts.OPERAND_PROCESS_HASH_MD5)
    if md5:
        add("this exact binary, by checksum",
            (RuleConsts.RULE_TYPE_SIMPLE, RuleConsts.OPERAND_PROCESS_HASH_MD5, md5))

    if con.dst_host != "" and con.dst_host != con.dst_ip:
        add("this host", from_dest_host(con.dst_host))
        for domain in dest_host_wildcards(con.dst_host):
            add("any host under %s" % domain, from_dest_host_wildcard(domain))

    if con.dst_ip != "":
        add("this address", from_dest_ip(con.dst_ip))
        try:
            for prefix in dest_ip_wildcards(con.dst_ip):
                add("any address under %s" % prefix, from_dest_ip_wildcard(prefix))
            for network in dest_networks(con.dst_ip):
                add("the network %s" % network, from_dest_network(network))
        except ValueError:
            pass

    if con.dst_port:
        add("port %s" % con.dst_port, from_dest_port(con.dst_port))
    if con.user_id is not None and int(con.user_id) >= 0:
        add("user %s" % con.user_id, from_user_id(con.user_id))
    if con.process_id is not None and int(con.process_id) > 0:
        add("this pid (%s)" % con.process_id, from_process_id(con.process_id))

    return found


def check_regexp(data):
    """returns an error string if the pattern won't work on the daemon side.

    The daemon compiles regexps with Go's RE2, which is more restrictive than
    Python's re: it has no lookaround and no backreferences.
    """
    try:
        re.compile(data)
    except re.error as e:
        return "invalid regular expression: {0}".format(e)

    for token, name in RE2_UNSUPPORTED:
        if token in data:
            return "the daemon's regexp engine (RE2) does not support {0} ({1})".format(name, token)
    if _BACKREF_RE.search(data):
        return "the daemon's regexp engine (RE2) does not support backreferences"

    return None
