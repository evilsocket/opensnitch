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

"""Starting and stopping the service.

Mirrors what bin/opensnitch-ui does to set up its gRPC server, so that a daemon
configured for either of them connects to the other without changes.
"""

import logging
import os
import signal
import socket
import threading
import time
from concurrent import futures

import grpc
from google.protobuf import json_format

from opensnitch import auth
from opensnitch.rule_consts import RuleConsts
from opensnitch.cli.proto import ui_pb2, ui_pb2_grpc
from opensnitch.cli import db as dbmod
from opensnitch.cli.policy import Policy
from opensnitch.cli.service import Service

logger = logging.getLogger(__name__)

OUTBOX_INTERVAL = 1.0
LAST_SEEN_INTERVAL = 30.0
PURGE_INTERVAL = 3600.0


def normalize_address(address):
    """grpc's python bindings don't take the abstract socket syntax the Go side uses."""
    if address.startswith("unix:@"):
        return "unix-abstract:{0}".format(address.split("@", 1)[1])
    return address


def unix_socket_path(address):
    if address.startswith("unix://"):
        return address[len("unix://"):]
    if address.startswith("unix:") and not address.startswith("unix:@"):
        return address[len("unix:"):]
    return None


def check_socket_free(sock_path):
    """refuses to start if something is already serving that socket.

    grpc does not fail when a unix socket is already there: it unlinks it and
    puts its own in its place, and add_insecure_port still reports success. So
    starting while opensnitch-ui is running would quietly take the daemon away
    from it. Ask the socket whether anyone is home instead.
    """
    if not os.path.exists(sock_path):
        return

    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(1)
    try:
        probe.connect(sock_path)
    except (ConnectionRefusedError, FileNotFoundError):
        # nothing behind it, it's left over from a process that died; grpc
        # replaces it when we bind
        logger.info("taking over the socket left behind at %s", sock_path)
        return
    except OSError:
        # can't tell, let grpc have a go
        return
    else:
        raise RuntimeError(
            "{0} is already being served. opensnitch-ui or another opensnitch-cli "
            "is using it, and a daemon can only talk to one of them".format(sock_path))
    finally:
        probe.close()


class Server:
    def __init__(self, config, database=None):
        self._config = config
        self._db = database if database is not None else dbmod.Database(config.db_path())
        self._policy = Policy(self._db, config)
        self._service = Service(self._db, self._policy, config)
        self._server = None
        self._exit = threading.Event()
        self._threads = []
        self._ntf_seq = 0

    @property
    def db(self):
        return self._db

    @property
    def service(self):
        return self._service

    def _options(self):
        maxmsg = self._config.getint("server", "max_message_length")
        options = [
            # https://github.com/grpc/grpc/blob/master/doc/keepalive.md
            ('grpc.keepalive_time_ms', self._config.getint("server", "keepalive")),
            ('grpc.keepalive_timeout_ms', self._config.getint("server", "keepalive_timeout")),
            ('grpc.keepalive_permit_without_calls', True),
            ('grpc.max_send_message_length', maxmsg),
            ('grpc.max_receive_message_length', maxmsg),
        ]
        max_clients = self._config.getint("server", "max_clients")
        if max_clients > 0:
            options.append(('grpc.max_allowed_incoming_connections', max_clients))
        return tuple(options)

    def start(self):
        address = normalize_address(self._config.get("server", "address"))
        sock_path = unix_socket_path(address)
        if sock_path is not None:
            directory = os.path.dirname(sock_path)
            if directory != "" and not os.path.isdir(directory):
                os.makedirs(directory, mode=0o700, exist_ok=True)
            check_socket_free(sock_path)

        # a worker is taken for as long as a node's notifications stream is
        # open, one more while a connection is being asked about, and Ping needs
        # one now and then: roughly three per node.
        workers = self._config.getint("server", "max_workers")
        self._server = grpc.server(futures.ThreadPoolExecutor(max_workers=workers),
                                   options=self._options())
        ui_pb2_grpc.add_UIServicer_to_server(self._service, self._server)

        auth_type = self._config.get("server", "auth_type")
        if auth_type in (auth.Simple, ""):
            port = self._server.add_insecure_port(address)
        else:
            creds = auth.get_tls_credentials(self._config.get("server", "tls_ca_cert"),
                                             self._config.get("server", "tls_cert"),
                                             self._config.get("server", "tls_key"))
            if creds is None:
                raise RuntimeError("invalid TLS credentials, check server.tls_cert and "
                                   "server.tls_key")
            port = self._server.add_secure_port(address, creds)

        # grpc reports a failure to bind by returning 0, it doesn't raise. The
        # usual reason is the graphical interface already listening there.
        if port == 0:
            raise RuntimeError(
                "could not listen on {0}. Is opensnitch-ui or another opensnitch-cli "
                "already using it?".format(address))

        self._server.start()

        if sock_path is not None:
            os.chmod(sock_path, 0o640)

        # anything still marked as sent was in flight when we stopped
        requeued = self._db.requeue_sent()
        if requeued:
            logger.info("re-queued %d notifications that were in flight", requeued)

        self._start_thread(self._outbox_loop, "outbox")
        self._start_thread(self._housekeeping_loop, "housekeeping")

        logger.info("listening on %s (auth: %s)", address, auth_type)
        logger.info("connections nobody has reviewed yet: %s for %s",
                    self._policy.action, self._policy.duration)
        if self._policy.action == RuleConsts.ACTION_ALLOW:
            logger.warning("unreviewed connections are ALLOWED until you review them. "
                           "Set policy.unreviewed_action to deny to block them instead")
        else:
            logger.info("unreviewed connections are blocked. Run 'opensnitch-cli review' "
                        "to go through them")
        return port

    def _start_thread(self, target, name):
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    def stop(self, grace=3):
        self._exit.set()
        self._service.shutdown()
        if self._server is not None:
            self._server.stop(grace).wait()
        for thread in self._threads:
            thread.join(timeout=2)
        self._db.close()
        logger.info("stopped")

    def serve_forever(self):
        self.start()

        def on_signal(signum, frame):
            logger.info("got signal %d, stopping", signum)
            self._exit.set()

        signal.signal(signal.SIGINT, on_signal)
        signal.signal(signal.SIGTERM, on_signal)

        while not self._exit.is_set():
            self._exit.wait(1)
        self.stop()

    # the outbox

    def _next_notification_id(self):
        """unique and increasing, the daemon echoes it back in its reply."""
        self._ntf_seq += 1
        return (int(time.time()) * 1000) + (self._ntf_seq % 1000)

    def drain_outbox(self):
        """sends the decisions taken by 'opensnitch-cli review'.

        Rows for a node that isn't connected stay queued, so a decision taken
        while the daemon is down is applied when it comes back. The queue is
        read per connected node: one query across all nodes would let a
        disconnected node's backlog fill the batch and starve the others.
        """
        sent = 0
        for node in self._service.nodes():
            if node.stop.is_set():
                continue
            for row in self._db.queued_notifications(node=node.addr):
                rule = ui_pb2.Rule()
                json_format.Parse(row["rule_json"], rule)

                ntf_id = self._next_notification_id()
                notification = ui_pb2.Notification(id=ntf_id, type=row["ntf_type"], rules=[rule])
                self._db.mark_sent(row["id"], ntf_id)
                node.queue.put(notification)
                sent += 1
                logger.info("sent %s for rule '%s' to %s",
                            ui_pb2.Action.Name(row["ntf_type"]), rule.name, row["node"])
        return sent

    def _outbox_loop(self):
        while not self._exit.is_set():
            try:
                self.drain_outbox()
            except Exception as e:
                logger.error("error draining the outbox: %s", repr(e))
            self._exit.wait(OUTBOX_INTERVAL)

    def _housekeeping_loop(self):
        retention = self._config.getint("db", "retention_days")
        last_purge = 0
        last_seen = 0
        while not self._exit.is_set():
            try:
                self._db.expire_provisionals()
                if time.time() - last_seen > LAST_SEEN_INTERVAL:
                    self._service.persist_last_seen(self._db)
                    last_seen = time.time()
                if time.time() - last_purge > PURGE_INTERVAL:
                    removed = self._db.purge(retention)
                    if removed:
                        logger.info("removed %d reviewed entries older than %d days",
                                    removed, retention)
                    last_purge = time.time()
            except Exception as e:
                logger.error("error in housekeeping: %s", repr(e))
            self._exit.wait(OUTBOX_INTERVAL)
