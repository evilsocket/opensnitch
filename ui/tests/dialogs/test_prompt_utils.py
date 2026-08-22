from PyQt6 import QtWidgets

from opensnitch.config import Config
from opensnitch.dialogs.prompt import constants
from opensnitch.dialogs.prompt import utils


class TestPromptUtils:

    def setup_method(self):
        Config.init()

    def test_add_container_options_to_combo(self, qtbot):
        combo = QtWidgets.QComboBox()
        qtbot.addWidget(combo)

        con = type("Conn", (), {
            "process_env": {
                "_OS_CONTAINER_ID": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "_OS_CONTAINER_CGROUP_PATH": "/system.slice/containerd.service/containerd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope",
            }
        })()

        utils.add_container_options_to_combo(combo, con)

        assert combo.count() == 2
        assert combo.itemData(0) == constants.FIELD_CGROUP_ID
        assert combo.itemData(1) == constants.FIELD_CGROUP_PATH

    def test_set_default_duration_for_container(self, qtbot):
        combo = QtWidgets.QComboBox()
        qtbot.addWidget(combo)
        for label in ["once", "30s", "5m", "15m", "30m", "1h", "12h", "until restart", "always"]:
            combo.addItem(label)

        con = type("Conn", (), {"process_env": {"_OS_CONTAINER_ID": "0123456789abcdef"}})()

        utils.set_default_duration(Config.get(), combo, con)

        assert combo.currentIndex() == 3

    def test_get_combo_operator_for_container_operands(self):
        con = type("Conn", (), {
            "process_env": {
                "_OS_CONTAINER_ID": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "_OS_CONTAINER_CGROUP_PATH": "/system.slice/containerd.service/containerd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope",
            },
            "process_path": "/usr/bin/python",
            "process_args": ["python", "app.py"],
            "process_id": 1234,
            "user_id": 1000,
            "dst_port": 443,
            "dst_ip": "1.2.3.4",
        })()

        rule_type, operand, value = utils.get_combo_operator(constants.FIELD_CGROUP_ID, "from container instance", con)
        assert rule_type == Config.RULE_TYPE_SIMPLE
        assert operand == Config.OPERAND_CGROUP_ID
        assert value == con.process_env["_OS_CONTAINER_ID"]

        rule_type, operand, value = utils.get_combo_operator(constants.FIELD_CGROUP_PATH, "from this container cgroup path", con)
        assert rule_type == Config.RULE_TYPE_SIMPLE
        assert operand == Config.OPERAND_CGROUP_PATH
        assert value == con.process_env["_OS_CONTAINER_CGROUP_PATH"]