
import json
from datetime import datetime

from google.protobuf.json_format import MessageToJson
from opensnitch.database import Database

class RxTx:
    def __init__(self, proto, addr, pb_alert):
        self._db = Database.instance()
        self.proto = proto
        self.addr = addr
        self.proc = json.loads(MessageToJson(pb_alert.proc))

        self.env = ""
        if self.proc.get('env') != None:
            self.env = json.dumps(self.proc['env'])
        self.tree = ""
        if self.proc.get('tree') != None:
            self.tree = json.dumps(self.proc['tree'])
        self.checksums=""
        if self.proc.get('checksums') != None:
            self.checksums = json.dumps(self.proc['checksums'])

        # totals
        self.bytesSent = 0
        self.bytesRecv = 0
        self.proto = ""
        if self.proc.get('bytesSent') != None:
            for k in self.proc['bytesSent']:
                self.bytesSent += int(self.proc['bytesSent'][k])
                self.proto = k
        if self.proc.get('bytesRecv') != None:
            for k in self.proc['bytesRecv']:
                self.bytesRecv += int(self.proc['bytesRecv'][k])
                self.proto = k
        self.cwd = ""
        if self.proc.get('cwd') != None:
            self.cwd = self.proc['cwd']

    def save(self):
        ret, lastId = self._db.insert("procs", "(what, hits)", (self.proc['path'], 0), action_on_conflict="IGNORE")
        # TODO: path is not valid as primary key. We should use
        # node+path as minimum.
        ret, lastId = self._db.insert("rxtx",
                                        "(time, what, proto, bytes_sent, bytes_recv, proc_path_fk)",
                                        (
                                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                            0, # process, conn, etc
                                            self.proto,
                                            self.bytesSent,
                                            self.bytesRecv,
                                            self.proc['path']
                                        ))
        ret, lastId = self._db.insert("proc_details",
                        "(time, node, comm, path, cmdline, cwd, md5, tree, env)",
                        (
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "{0}:{1}".format(self.proto, self.addr),
                            self.proc['comm'],
                            self.proc['path'],
                            " ".join(self.proc['args']),
                            self.cwd,
                            self.checksums,
                            self.tree,
                            self.env
                        ), action_on_conflict="IGNORE")
