#
# pytest -v cli/test_match.py
#
# match.py answers "would the daemon still ask about this connection if that
# rule were installed?". A false positive silently loses a queue entry, so the
# tests care most about the cases that must answer None ("can't tell").
#

from opensnitch.cli import match, rules
from opensnitch.cli.proto import ui_pb2


def op(op_type, operand, data, sensitive=False):
    return rules.new_operator(op_type, operand, data, sensitive=sensitive)


class TestSimple:

    def test_the_executable_matches(self, connection):
        assert match.operator_matches(
            op("simple", "process.path", "/usr/bin/curl"), connection) is True

    def test_a_different_executable_does_not(self, connection):
        assert match.operator_matches(
            op("simple", "process.path", "/usr/bin/wget"), connection) is False

    def test_not_case_sensitive_by_default(self, connection):
        """the daemon compares with strings.EqualFold unless sensitive is set."""
        assert match.operator_matches(
            op("simple", "dest.host", "API.GITHUB.COM"), connection) is True
        assert match.operator_matches(
            op("simple", "dest.host", "API.GITHUB.COM", sensitive=True),
            connection) is False

    def test_ports_and_users_are_compared_as_strings(self, connection):
        assert match.operator_matches(op("simple", "dest.port", "443"), connection) is True
        assert match.operator_matches(op("simple", "user.id", "1000"), connection) is True
        assert match.operator_matches(op("simple", "dest.port", "80"), connection) is False

    def test_the_command_line_is_the_joined_argv(self, connection):
        assert match.operator_matches(
            op("simple", "process.command",
               "/usr/bin/curl -sSL https://api.github.com/repos"), connection) is True

    def test_an_operand_we_cannot_read_is_unknown(self, connection):
        """iface.out lives on the daemon's packet, not on the connection."""
        assert match.operator_matches(op("simple", "iface.out", "eth0"), connection) is None

    def test_a_checksum_only_matches_when_it_is_ours(self, connection):
        """without a checksum the daemon fakes a match; we can't tell, so None."""
        assert match.operator_matches(
            op("simple", "process.hash.md5", "d41d8..."), connection) is None

        connection.process_checksums["process.hash.md5"] = "abc123"
        assert match.operator_matches(
            op("simple", "process.hash.md5", "abc123"), connection) is True
        assert match.operator_matches(
            op("simple", "process.hash.md5", "otherhash"), connection) is None


class TestRegexp:

    def test_the_host_wildcard_covers_subdomains_and_the_bare_domain(self, connection):
        wildcard = op("regexp", "dest.host", r"^(|.*\.)github\.com$")
        assert match.operator_matches(wildcard, connection) is True

        connection.dst_host = "github.com"
        assert match.operator_matches(wildcard, connection) is True

        connection.dst_host = "notgithub.com"
        assert match.operator_matches(wildcard, connection) is False

    def test_lowercased_like_the_daemon_when_not_sensitive(self, connection):
        assert match.operator_matches(
            op("regexp", "dest.host", r"API\.GITHUB\.com"), connection) is True

    def test_a_pattern_that_does_not_compile_is_unknown(self, connection):
        assert match.operator_matches(
            op("regexp", "dest.host", "("), connection) is None


class TestNetwork:

    def test_the_destination_network(self, connection):
        assert match.operator_matches(
            op("network", "dest.network", "140.82.0.0/16"), connection) is True
        assert match.operator_matches(
            op("network", "dest.network", "10.0.0.0/8"), connection) is False

    def test_an_alias_only_resolves_on_the_daemon(self, connection):
        assert match.operator_matches(
            op("network", "dest.network", "lan"), connection) is None


class TestList:

    def test_every_operand_has_to_match(self, connection):
        rule = rules.build_rule("r", "allow", "always", [
            op("simple", "process.path", "/usr/bin/curl"),
            op("simple", "dest.port", "443")])
        assert match.rule_matches(rule, connection) is True

    def test_one_mismatch_settles_it(self, connection):
        rule = rules.build_rule("r", "allow", "always", [
            op("simple", "process.path", "/usr/bin/curl"),
            op("simple", "dest.port", "80")])
        assert match.rule_matches(rule, connection) is False

    def test_one_unknown_spoils_the_whole_list(self, connection):
        """a mismatch elsewhere still decides, but 'all matched' can't be claimed."""
        rule = rules.build_rule("r", "allow", "always", [
            op("simple", "process.path", "/usr/bin/curl"),
            op("simple", "iface.out", "eth0")])
        assert match.rule_matches(rule, connection) is None

        rule = rules.build_rule("r", "allow", "always", [
            op("simple", "process.path", "/usr/bin/wget"),
            op("simple", "iface.out", "eth0")])
        assert match.rule_matches(rule, connection) is False


class TestRule:

    def test_a_disabled_rule_matches_nothing(self, connection):
        rule = rules.build_rule("r", "allow", "always",
                                [op("simple", "process.path", "/usr/bin/curl")],
                                enabled=False)
        assert match.rule_matches(rule, connection) is False

    def test_the_true_operand_matches_everything(self, connection):
        rule = ui_pb2.Rule(name="r", enabled=True, action="allow", duration="always")
        rule.operator.type = "simple"
        rule.operator.operand = "true"
        assert match.rule_matches(rule, connection) is True

    def test_a_type_we_do_not_understand_is_unknown(self, connection):
        rule = rules.build_rule("r", "allow", "always",
                                [op("lists", "lists.domains", "/etc/lists")])
        assert match.rule_matches(rule, connection) is None
