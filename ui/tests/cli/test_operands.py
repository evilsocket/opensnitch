#
# pytest -v cli/test_operands.py
#
# The patterns built here end up in the daemon's rules, and the pop-up builds
# the same ones. test_operands_parity.py checks they stay identical.

import pytest

from opensnitch import operands
from opensnitch.cli.proto import ui_pb2


def make_connection(**kwargs):
    fields = dict(protocol="tcp", dst_ip="140.82.121.6", dst_host="api.github.com",
                  dst_port=443, user_id=1000, process_id=41233,
                  process_path="/usr/bin/curl",
                  process_args=["/usr/bin/curl", "-sSL", "https://api.github.com"])
    fields.update(kwargs)
    return ui_pb2.Connection(**fields)


class TestBuilders:

    def test_host_wildcard_matches_the_domain_and_its_subdomains(self):
        assert operands.from_dest_host_wildcard("github.com") == \
            ("regexp", "dest.host", r"^(|.*\.)github\.com$")

    def test_address_wildcard(self):
        assert operands.from_dest_ip_wildcard("140.82.*") == \
            ("regexp", "dest.ip", r"140\.82\..*")

    def test_command_line(self):
        con = make_connection()
        assert operands.from_process_command(con.process_args, con.process_path) == \
            ("simple", "process.command", "/usr/bin/curl -sSL https://api.github.com")

    def test_command_line_falls_back_to_the_executable(self):
        assert operands.from_process_command([], "/usr/bin/curl") == \
            ("simple", "process.path", "/usr/bin/curl")

    def test_appimage_ignores_the_mount_point(self):
        _, operand, data = operands.from_appimage_path("/tmp/.mount_Eden8xK2p/usr/bin/eden")
        assert operand == "process.path"
        assert "[0-9A-Za-z]+" in data and data.endswith("eden$")

    def test_snap_ignores_the_revision(self):
        _, operand, data = operands.from_snap_path("/snap/firefox/4259/usr/lib/firefox/firefox")
        assert operand == "process.path"
        assert "[0-9]+" in data


class TestCandidates:

    def test_offers_the_executable_first(self):
        found = operands.candidates(make_connection())
        assert found[0]["operand"] == "process.path"
        assert found[0]["data"] == "/usr/bin/curl"

    def test_offers_command_line_host_address_and_wildcards(self):
        found = operands.candidates(make_connection())
        pairs = [(c["type"], c["operand"], c["data"]) for c in found]

        assert ("simple", "process.command", "/usr/bin/curl -sSL https://api.github.com") in pairs
        assert ("simple", "dest.host", "api.github.com") in pairs
        assert ("regexp", "dest.host", r"^(|.*\.)github\.com$") in pairs
        assert ("simple", "dest.ip", "140.82.121.6") in pairs
        assert ("regexp", "dest.ip", r"140\.82\..*") in pairs
        assert ("network", "dest.network", "140.82.121.0/24") in pairs
        assert ("simple", "dest.port", "443") in pairs
        assert ("simple", "user.id", "1000") in pairs

    def test_skips_what_is_not_known(self):
        con = ui_pb2.Connection(protocol="tcp", dst_ip="10.0.0.1", dst_port=25,
                                process_path="", user_id=0)
        pairs = [c["operand"] for c in operands.candidates(con)]
        assert "process.path" not in pairs
        assert "dest.ip" in pairs

    def test_ipv6(self):
        con = make_connection(dst_ip="2606:2800:220:1:248:1893:25c8:1946", dst_host="")
        pairs = [(c["operand"], c["data"]) for c in operands.candidates(con)]
        assert any(operand == "dest.network" and data.endswith("/64") for operand, data in pairs)

    def test_appimage_offered_first_for_an_appimage(self):
        con = make_connection(process_path="/tmp/.mount_Eden8xK2p/usr/bin/eden")
        assert operands.candidates(con)[0]["type"] == "regexp"

    def test_every_candidate_is_usable(self):
        """nothing we offer may be something the daemon would refuse."""
        from opensnitch.cli import rules

        for cand in operands.candidates(make_connection()):
            op = rules.new_operator(cand["type"], cand["operand"], cand["data"])
            assert rules.validate_operator(op) is None, cand


class TestRE2:

    @pytest.mark.parametrize("pattern,expected_ok", [
        (r"^(|.*\.)github\.com$", True),
        (r"140\.82\..*", True),
        (r"^(?=x)", False),
        (r"(?!x)", False),
        (r"(?<=a)b", False),
        (r"(a)\1", False),
        (r"[", False),
    ])
    def test_check_regexp(self, pattern, expected_ok):
        assert (operands.check_regexp(pattern) is None) == expected_ok
