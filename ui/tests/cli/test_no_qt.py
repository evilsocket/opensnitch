#
# pytest -v cli/test_no_qt.py
#
# opensnitch-cli must run on servers where PyQt is not installed. This walks the
# package and fails if anything reaches Qt, directly or through an import.

import importlib
import os
import subprocess
import sys

MODULES = (
    "opensnitch.rule_consts",
    "opensnitch.operands",
    "opensnitch.proto",
    "opensnitch.cli.config",
    "opensnitch.cli.durations",
    "opensnitch.cli.db",
    "opensnitch.cli.proto",
    "opensnitch.cli.rules",
    "opensnitch.cli.policy",
    "opensnitch.cli.service",
    "opensnitch.cli.server",
    "opensnitch.cli.review",
    "opensnitch.cli.main",
)


class TestNoQt:

    def test_modules_do_not_import_qt(self):
        """importing the whole CLI must not pull PyQt in.

        Run in a new interpreter, so that a GUI test that ran earlier in the
        session can't make this pass by accident.
        """
        script = (
            "import sys\n"
            "for name in %r:\n"
            "    __import__(name)\n"
            "leaked = [m for m in sys.modules if m.startswith('PyQt')]\n"
            "print(','.join(leaked))\n" % (MODULES,)
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(sys.path)
        result = subprocess.run([sys.executable, "-c", script],
                                capture_output=True, text=True, env=env)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "", \
            "the CLI imported Qt: %s" % result.stdout.strip()

    def test_modules_import(self):
        for name in MODULES:
            importlib.import_module(name)
