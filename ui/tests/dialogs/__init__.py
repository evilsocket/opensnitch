
from opensnitch.database import Database
from opensnitch.config import Config
from opensnitch.nodes import Nodes

# grpc object
class ClientConfig:
    version = "1.2.3"
    name = "bla"
    logLevel = 0
    isFirewallRunning = False
    rules = []
    config = '''{
    "Server":{
        "Address": "unix:///tmp/osui.sock",
        "LogFile": "/var/log/opensnitchd.log"
    },
    "DefaultAction": "deny",
    "DefaultDuration": "once",
    "InterceptUnknown": false,
    "ProcMonitorMethod": "ebpf",
    "LogLevel": 0,
    "LogUTC": true,
    "LogMicro": false,
    "Firewall": "iptables",
    "Stats": {
        "MaxEvents": 150,
        "MaxStats": 50
    }
    }
    '''

class Connection:
    protocol = "tcp"
    src_ip = "127.0.0.1"
    src_port = "12345"
    dst_ip = "127.0.0.1"
    dst_host = "localhost"
    dst_port = "54321"
    user_id = 1000
    process_id = 9876
    process_path = "/bin/cmd"
    process_cwd = "/tmp"
    process_args = "/bin/cmd --parm1 test"
    process_env = []

db = Database.instance()
db.initialize()
Config.init()

nodes = Nodes.instance()
nodes._nodes["unix:/tmp/osui.sock"] = {
    'data': ClientConfig
}
