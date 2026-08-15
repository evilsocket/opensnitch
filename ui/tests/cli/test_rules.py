#
# pytest -v cli/test_rules.py
#

import pytest

from opensnitch.cli import durations, rules
from opensnitch.rule_consts import RuleConsts


class TestDurations:

    @pytest.mark.parametrize("value", ["30s", "5m", "1h", "12h", "1h30m", "always",
                                       "until restart", "once"])
    def test_accepted(self, value):
        assert durations.validate(value) is None

    @pytest.mark.parametrize("value", ["1d", "1w", "banana", "", "1", "-5m"])
    def test_refused(self, value):
        """Go's time.ParseDuration has no days or weeks.

        The daemon throws away the parsing error, so a rule with an unparseable
        duration is never scheduled for removal and lives until it restarts.
        """
        assert durations.validate(value) is not None

    def test_to_seconds(self):
        assert durations.to_seconds("1h30m") == 5400
        assert durations.to_seconds("30s") == 30
        assert durations.to_seconds("always") is None

    def test_is_temporary(self):
        assert durations.is_temporary("1h")
        assert not durations.is_temporary("always")
        assert not durations.is_temporary("until restart")
        # the daemon does not schedule "once" rules for removal either
        assert not durations.is_temporary("once")


class TestBuildRule:

    def test_single_operand_is_flattened(self):
        op = rules.new_operator("simple", "process.path", "/usr/bin/curl")
        rule = rules.build_rule("r", "allow", "always", [op])

        assert rule.operator.type == "simple"
        assert rule.operator.data == "/usr/bin/curl"
        assert len(rule.operator.list) == 0

    def test_several_operands_become_a_list(self):
        ops = [rules.new_operator("simple", "process.path", "/usr/bin/curl"),
               rules.new_operator("simple", "dest.port", "443")]
        rule = rules.build_rule("r", "allow", "always", ops)

        assert rule.operator.type == RuleConsts.RULE_TYPE_LIST
        assert rule.operator.operand == RuleConsts.RULE_TYPE_LIST
        # the daemon reads the operands from the list, not from data
        assert rule.operator.data == ""
        assert len(rule.operator.list) == 2

    def test_name_matches_the_popup_convention(self):
        assert rules.rule_name("allow", "always", False, "/usr/bin/curl") == \
            "allow-always-simple-usr-bin-curl"

    def test_a_list_rule_is_named_after_every_condition(self):
        """also the pop-up's convention (dialogs/prompt/dialog.py _send_rule)"""
        assert rules.rule_name("allow", "always", True, "/usr/bin/curl",
                               ["api.github.com", "443"]) == \
            "allow-always-list-usr-bin-curl-api-github-com-443"

    def test_unique_name_avoids_a_rename_by_the_daemon(self):
        taken = {"allow-always-simple-x", "allow-always-simple-x-2"}
        assert rules.unique_name("allow-always-simple-x", taken) == "allow-always-simple-x-3"


class TestValidation:

    def test_accepts_a_normal_rule(self):
        op = rules.new_operator("simple", "process.path", "/usr/bin/curl")
        assert rules.validate_rule(rules.build_rule("r", "allow", "always", [op])) is None

    def test_refuses_once(self):
        """a "once" rule sent over the notifications channel never expires."""
        op = rules.new_operator("simple", "process.path", "/x")
        error = rules.validate_rule(rules.build_rule("r", "allow", "once", [op]))
        assert error is not None and "once" in error

    def test_refuses_days(self):
        op = rules.new_operator("simple", "process.path", "/x")
        assert rules.validate_rule(rules.build_rule("r", "allow", "2d", [op])) is not None

    def test_refuses_an_unknown_action(self):
        op = rules.new_operator("simple", "process.path", "/x")
        assert rules.validate_rule(rules.build_rule("r", "explode", "always", [op])) is not None

    def test_network_type_needs_the_network_operand(self):
        bad = rules.new_operator("network", "dest.ip", "10.0.0.0/8")
        assert rules.validate_operator(bad) is not None
        good = rules.new_operator("network", "dest.network", "10.0.0.0/8")
        assert rules.validate_operator(good) is None

    def test_empty_data_only_allowed_for_some_types(self):
        # simple and regexp may match an empty string, network may not
        assert rules.validate_operator(rules.new_operator("simple", "dest.host", "")) is None
        assert rules.validate_operator(rules.new_operator("regexp", "dest.host", "")) is None
        assert rules.validate_operator(
            rules.new_operator("network", "dest.network", "")) is not None

    @pytest.mark.parametrize("pattern", [r"^(?=x)foo$", r"(?!x)", r"(?<=a)b", r"(a)\1"])
    def test_refuses_patterns_go_cannot_compile(self, pattern):
        """Go uses RE2: no lookaround, no backreferences."""
        op = rules.new_operator("regexp", "dest.host", pattern)
        assert rules.validate_operator(op) is not None

    def test_accepts_the_wildcard_the_popup_builds(self):
        op = rules.new_operator("regexp", "dest.host", r"^(|.*\.)github\.com$")
        assert rules.validate_operator(op) is None

    def test_refuses_a_broken_pattern(self):
        assert rules.validate_operator(rules.new_operator("regexp", "dest.host", "[")) is not None


class TestWarnings:

    def test_upper_case_regexp_would_never_match(self):
        """the daemon lowercases a non case sensitive pattern before compiling."""
        op = rules.new_operator("regexp", "dest.host", r"^GitHub\.com$")
        assert rules.case_warning(op) is not None

    def test_no_warning_when_case_sensitive(self):
        op = rules.new_operator("regexp", "dest.host", r"^GitHub\.com$", sensitive=True)
        assert rules.case_warning(op) is None

    def test_no_warning_for_lower_case(self):
        op = rules.new_operator("regexp", "dest.host", r"^github\.com$")
        assert rules.case_warning(op) is None
