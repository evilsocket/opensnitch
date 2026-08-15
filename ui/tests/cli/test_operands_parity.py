#
# pytest -v cli/test_operands_parity.py
#
# The pop-up and opensnitch-cli must build exactly the same rules for the same
# connection: a rule created from a terminal has to behave like one created from
# the graphical interface. get_combo_operator() delegates to opensnitch.operands,
# and this makes sure it stays that way.
#
# Skipped where Qt is not installed, which is the normal case on a server.

import pytest

pytest.importorskip("PyQt6")

from opensnitch import operands                                    # noqa: E402
from opensnitch.cli.proto import ui_pb2                            # noqa: E402
from opensnitch.dialogs.prompt import utils as prompt_utils        # noqa: E402


def make_connection(**kwargs):
    fields = dict(protocol="tcp", dst_ip="140.82.121.6", dst_host="api.github.com",
                  dst_port=443, user_id=1000, process_id=41233,
                  process_path="/usr/bin/curl",
                  process_args=["/usr/bin/curl", "-sSL", "https://api.github.com"])
    fields.update(kwargs)
    return ui_pb2.Connection(**fields)


CONNECTIONS = {
    "curl": make_connection(),
    "no args": make_connection(process_args=[]),
    "empty arg": make_connection(process_args=[""]),
    "appimage": make_connection(process_path="/tmp/.mount_Eden8xK2p/usr/bin/eden"),
    "snap": make_connection(process_path="/snap/firefox/4259/usr/lib/firefox/firefox"),
    "dotted path": make_connection(process_path="/opt/my.app/bin/my.bin"),
}

# (field, what the combo shows, the value the builders take)
CASES = [
    (operands.FIELD_PROC_PATH, "from this executable", None),
    (operands.FIELD_PROC_ARGS, "from this command line", None),
    (operands.FIELD_PROC_ID, "from this PID", None),
    (operands.FIELD_USER_ID, "from user 1000", None),
    (operands.FIELD_DST_PORT, "to port 443", None),
    (operands.FIELD_DST_IP, "to 140.82.121.6", None),
    (operands.FIELD_DST_HOST, "api.github.com", "api.github.com"),
    (operands.FIELD_DST_NETWORK, "to 140.82.121.0/24", "140.82.121.0/24"),
    (operands.FIELD_DST_NETWORK, "to 140.0.0.0/8", "140.0.0.0/8"),
    (operands.FIELD_REGEX_HOST, "to *.github.com", "github.com"),
    (operands.FIELD_REGEX_HOST, "to *.co.uk", "co.uk"),
    (operands.FIELD_REGEX_IP, "to 140.82.*", "140.82.*"),
    (operands.FIELD_REGEX_IP, "to 140.*", "140.*"),
    (operands.FIELD_APPIMAGE, "from /tmp/.mount_Eden8*/eden", None),
    (operands.FIELD_SNAP, "from /snap/firefox/*/usr/lib/firefox/firefox", None),
]


class TestParity:

    @pytest.mark.parametrize("con_name", list(CONNECTIONS.keys()))
    def test_same_operator_as_the_popup(self, con_name):
        con = CONNECTIONS[con_name]
        for field, combo_text, value in CASES:
            from_popup = prompt_utils.get_combo_operator(field, combo_text, con)
            from_cli = operands.get_operator(field, value, con)
            assert from_popup == from_cli, \
                "%s / %s: pop-up %r, cli %r" % (con_name, field, from_popup, from_cli)

    def test_the_candidate_list_agrees_with_the_popup(self):
        """what the terminal offers must be what the pop-up would have built."""
        con = CONNECTIONS["curl"]

        wildcard = [c for c in operands.candidates(con)
                    if c["type"] == "regexp" and c["operand"] == "dest.host"][0]
        from_popup = prompt_utils.get_combo_operator(
            operands.FIELD_REGEX_HOST, "to *.github.com", con)
        assert (wildcard["type"], wildcard["operand"], wildcard["data"]) == from_popup
