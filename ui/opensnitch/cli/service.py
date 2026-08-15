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

"""The service the daemon connects to.

Note the direction: the daemon is the gRPC client and dials us, the same way it
dials the graphical interface (opensnitch/service.py). Only one of the two can
own a given socket, so a machine runs either the GUI or this, not both.
"""

import copy
import json
import logging
import queue
import threading
import time

from packaging.version import Version, InvalidVersion

from opensnitch.version import version as client_version
from opensnitch.cli.proto import ui_pb2, ui_pb2_grpc

logger = logging.getLogger(__name__)

# put on a node's queue to close its notifications stream. The daemon ends the
# stream for any notification type <= NONE (daemon/ui/notifications.go).
CLOSE_STREAM = -1

# The notification types were renumbered in 1.6.0 (proto/ui.proto enum Action).
# An older daemon does not reject what we send, it misreads it: our CHANGE_RULE
# is its MONITOR_PROCESS and our DELETE_RULE is its STOP, so every decision
# would be silently thrown away while we record it as delivered.
MIN_DAEMON_VERSION = "1.6.0"


def version_warning(daemon_version):
    """what to tell the operator about a daemon's version, or None."""
    try:
        theirs = Version(daemon_version)
    except InvalidVersion:
        return None
    if theirs < Version(MIN_DAEMON_VERSION):
        return ("daemon version {0} is older than {1}: it will misread the rules this "
                "client sends and none of your decisions will take effect. Upgrade the "
                "daemon.".format(daemon_version, MIN_DAEMON_VERSION))
    try:
        if theirs != Version(client_version):
            return ("daemon version {0} differs from this client's {1}; the two are "
                    "expected to interoperate, but keep them in step if something "
                    "looks off".format(daemon_version, client_version))
    except InvalidVersion:
        pass
    return None


class Node:
    def __init__(self, addr, peer):
        self.addr = addr
        self.peer = peer
        self.queue = queue.Queue()
        self.stop = threading.Event()
        self.hostname = ""
        self.version = ""
        self.last_seen = time.time()


class Service(ui_pb2_grpc.UIServicer):
    """implements the five calls the daemon makes."""

    def __init__(self, db, policy, config):
        self._db = db
        self._policy = policy
        self._config = config
        self._default_action = config.get("policy", "default_action")
        self._store_alerts = config.getbool("log", "store_alerts")

        self._nodes = {}
        self._lock = threading.RLock()
        self._exit = threading.Event()

    # node bookkeeping

    def peer_addr(self, peer):
        """the key we store a node under.

        Same shape the GUI uses (opensnitch/nodes.py get_addr): "proto:host",
        with a placeholder for unix sockets, whose peer has no address. The
        port is dropped on purpose: over TCP the peer is the daemon's ephemeral
        source port, which changes every time it reconnects, and the outbox is
        keyed by this value — keeping the port would leave every decision taken
        while the daemon was down addressed to a node that never comes back.
        """
        proto, _, addr = peer.partition(":")
        if proto.startswith("unix"):
            return "%s:%s" % (proto, addr if addr != "" else "/local")
        if addr.startswith("["):
            # ipv6:[::1]:59680
            host = addr[:addr.find("]") + 1] if "]" in addr else addr
        else:
            # ipv4:192.168.1.5:41000
            host = addr.rsplit(":", 1)[0] if ":" in addr else addr
        return "%s:%s" % (proto, host)

    def get_node(self, addr):
        with self._lock:
            return self._nodes.get(addr)

    def nodes(self):
        with self._lock:
            return list(self._nodes.values())

    def persist_last_seen(self, db):
        """writes when each node was last heard from.

        Ping arrives once a second per node, so it only updates the value in
        memory; this is called from the housekeeping thread now and then.
        """
        for node in self.nodes():
            if node.stop.is_set():
                continue
            db.node_seen(node.addr, node.hostname, node.version, online=True)

    def shutdown(self):
        """asks every daemon to close its notifications stream."""
        self._exit.set()
        for node in self.nodes():
            node.stop.set()
            node.queue.put(ui_pb2.Notification(id=0, type=CLOSE_STREAM))

    # the RPCs

    def Ping(self, request, context):
        """heartbeat, once a second per node, with a one second deadline.

        Keep it cheap: no database write on this path. The statistics the daemon
        sends are ignored for now, the review queue is fed by AskRule.
        """
        addr = self.peer_addr(context.peer())
        node = self.get_node(addr)
        if node is not None:
            node.last_seen = time.time()
        # the daemon checks that the id it sent comes back
        return ui_pb2.PingReply(id=request.id)

    def Subscribe(self, node_config, context):
        """a daemon introduces itself.

        Registering must finish before Notifications arrives, otherwise the
        stream is refused. We have no event loop, so unlike the GUI we simply do
        it before returning.
        """
        peer = context.peer()
        addr = self.peer_addr(peer)

        # Always a fresh Node. A daemon reconnecting over a unix socket shows up
        # with the same peer string as before, and the old Node's stop event was
        # set when its stream closed; reusing it would end the new notifications
        # stream immediately, and the daemon would reconnect in a loop from then
        # on. The old session, if one is somehow still open, ends through its own
        # Node's stop event.
        with self._lock:
            old = self._nodes.get(addr)
            node = Node(addr, peer)
            node.hostname = node_config.name
            node.version = node_config.version
            self._nodes[addr] = node
        if old is not None:
            old.stop.set()

        self._db.node_seen(addr, node_config.name, node_config.version, online=True)
        self._db.replace_rules(addr, node_config.rules)

        logger.info("node connected: %s (%s, daemon %s), %d rules", addr, node_config.name,
                    node_config.version, len(node_config.rules))
        warning = version_warning(node_config.version)
        if warning is not None:
            logger.warning("%s: %s", addr, warning)
        return self._with_default_action(node_config)

    def _with_default_action(self, node_config):
        """tells the daemon what to do when we can't answer.

        The daemon uses this for connections that arrive while it's already
        waiting for an answer to another one, and when a call to us fails. It
        only applies while we're connected and is not written to disk. Same as
        the GUI's _overwrite_nodes_config().
        """
        new_config = copy.deepcopy(node_config)
        try:
            config = json.loads(new_config.config)
            config['DefaultAction'] = self._default_action
            new_config.config = json.dumps(config)
        except Exception as e:
            logger.warning("could not read the node's configuration, leaving it alone: %s",
                           repr(e))
            return node_config
        return new_config

    def AskRule(self, request, context):
        """a connection the daemon has no rule for.

        Answered immediately, see opensnitch/cli/policy.py. Returning None makes
        the daemon apply its default action.
        """
        addr = self.peer_addr(context.peer())
        rule = self._policy.on_ask(addr, request)
        if rule is None:
            return None

        logger.info("%s: %s -> %s:%d, answering %s %s", addr,
                    request.process_path or "?",
                    request.dst_host or request.dst_ip, request.dst_port,
                    rule.action, rule.duration)
        return rule

    def Notifications(self, node_iter, context):
        """the channel we send rule changes on, and the daemon replies on."""
        peer = context.peer()
        addr = self.peer_addr(peer)
        node = self.get_node(addr)
        if node is None:
            logger.warning("notifications from an unknown node: %s", addr)
            return

        def on_closed():
            node.stop.set()
            self._on_stream_closed(node)

        context.add_callback(on_closed)

        reader = threading.Thread(target=self._read_replies, args=(node, node_iter),
                                  name="replies-%s" % addr, daemon=True)
        reader.start()

        while not node.stop.is_set() and not self._exit.is_set():
            try:
                notification = node.queue.get(timeout=1)
            except queue.Empty:
                continue
            if notification.type == CLOSE_STREAM:
                break
            yield notification

    def _read_replies(self, node, node_iter):
        """records what the daemon made of the notifications we sent."""
        try:
            for reply in node_iter:
                # the daemon opens the stream with an id of 0, before we've sent
                # anything (daemon/ui/notifications.go listenForNotifications)
                if reply.id == 0:
                    continue
                ok = reply.code == ui_pb2.OK
                if not ok:
                    logger.error("node %s rejected notification %d: %s",
                                 node.addr, reply.id, reply.data)
                self._db.mark_result(reply.id, ok, None if ok else reply.data)
        except Exception as e:
            logger.debug("notifications stream of %s closed: %s", node.addr, repr(e))
        finally:
            node.stop.set()
            self._on_stream_closed(node)

    def _on_stream_closed(self, node):
        """a notification stream ended, cleanly or not.

        Anything sent on it and not yet answered goes back in the queue, to be
        sent again when the daemon comes back: re-sending is safe, the daemon
        replaces rules by name and deleting a rule that isn't there does nothing.
        The node is only marked offline if a newer session hasn't replaced it.
        """
        requeued = self._db.requeue_sent(node.addr)
        if requeued:
            logger.info("%s went away with %d unanswered notifications, "
                        "they will be sent again when it returns", node.addr, requeued)

        with self._lock:
            current = self._nodes.get(node.addr) is node
        if current:
            logger.info("node disconnected: %s", node.addr)
            self._db.node_offline(node.addr)

    def PostAlert(self, alert, context):
        addr = self.peer_addr(context.peer())
        if self._store_alerts:
            try:
                self._db.add_alert(addr, alert)
            except Exception as e:
                logger.warning("could not store alert: %s", repr(e))
        return ui_pb2.MsgResponse(id=0)
