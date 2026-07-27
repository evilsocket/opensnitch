#
# pytest -v tests/dialogs/test_prompt_utils.py
#

import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

from opensnitch.config import Config
from opensnitch.dialogs.prompt import utils


def _make_rule(data, rule_type=Config.RULE_TYPE_REGEXP):
    rule = ui_pb2.Rule(name="user.choice")
    rule.action = Config.ACTION_ALLOW
    rule.duration = Config.DURATION_ONCE
    rule.operator.type = rule_type
    rule.operator.operand = Config.OPERAND_PROCESS_PATH
    rule.operator.data = data
    return rule


class TestPromptUtils():

    def test_get_rule_name_appimage_regexp_no_duplicated_class(self):
        """ Regexps built for appimage/snap paths use a mixed-case character
        class ([0-9A-Za-z]). slugify() lowercases everything, which used to
        turn it into "0-9a-za-z" in the rule name, looking like a duplicated
        a-z class (#1587).
        """
        rule = _make_rule(r'^/tmp/\.mount_handy_[0-9A-Za-z]+\/.*handy$')
        name = utils.get_rule_name(rule, False)

        assert "0-9a-za-z" not in name
        assert "handy" in name

    def test_get_rule_name_simple_rule_unaffected(self):
        """ Non-regexp rules aren't touched by the character-class stripping.
        """
        rule = _make_rule("www.google.com", rule_type=Config.RULE_TYPE_SIMPLE)
        name = utils.get_rule_name(rule, False)

        assert name == "allow-once-simple-www-google-com"

    def test_get_rule_name_escaped_brackets_not_mangled(self):
        """ A hand-typed regexp matching a literal bracket must not be
        treated as a character class and stripped.
        """
        rule = _make_rule(r'^/opt/\[legacy\]/app$')
        name = utils.get_rule_name(rule, False)

        assert "legacy" in name
        assert "app" in name
