# conftest.py - pytest configuration for opensnitch UI tests
#
# This file sets up Qt and database before tests run.

import pytest
from PyQt6 import QtWidgets
from unittest.mock import patch
from queue import Queue

# Global flag to track initialization
_initialized = False

# Isolation: the tests write QSettings (~/.config/opensnitch/settings.conf),
# delete settings.conf, and toggle the autostart .desktop file. Redirect HOME
# and the XDG dirs to a throwaway directory *before* opensnitch or Qt cache
# any path, so a test run never touches an installed OpenSnitch UI.
import hashlib
import os
import pwd
import shutil
import sys
import tempfile

if any(m == "opensnitch" or m.startswith("opensnitch.") for m in sys.modules):
    raise RuntimeError("opensnitch was imported before tests/conftest.py could isolate HOME; refusing to run")

_REAL_HOME = pwd.getpwuid(os.getuid()).pw_dir
_SANDBOX = tempfile.mkdtemp(prefix="opensnitch-ui-tests-")
for _var, _sub in (
        ("HOME", ""),
        ("XDG_CONFIG_HOME", ".config"),
        ("XDG_DATA_HOME", ".local/share"),
        ("XDG_CACHE_HOME", ".cache"),
        ("XDG_STATE_HOME", ".local/state"),
        ("XDG_RUNTIME_DIR", "run")):
    _path = os.path.join(_SANDBOX, _sub)
    os.makedirs(_path, mode=0o700, exist_ok=True)
    os.environ[_var] = _path
# no desktop notifications or other D-Bus traffic to the real session
os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)

# files of a real installation that a test run must never modify
_REAL_FILES = [
    os.path.join(_REAL_HOME, ".config/opensnitch/settings.conf"),
    os.path.join(_REAL_HOME, ".config/autostart/opensnitch_ui.desktop"),
]

def _snapshot_real_files():
    snap = {}
    for path in _REAL_FILES:
        try:
            with open(path, "rb") as f:
                snap[path] = hashlib.sha256(f.read()).hexdigest()
        except FileNotFoundError:
            snap[path] = None
    return snap

def init_test_environment():
    """Initialize database and config after QApplication exists."""
    global _initialized
    if _initialized:
        return

    from opensnitch.database import Database
    from opensnitch.config import Config
    from opensnitch.nodes import Nodes

    db = Database.instance()
    db.initialize()
    Config.init()

    # Setup mock node with full structure
    from tests.dialogs import ClientConfig
    nodes = Nodes.instance()
    nodes._nodes["unix:/tmp/osui.sock"] = {
        'data': ClientConfig,
        'notifications': Queue(),
        'online': True
    }

    _initialized = True

@pytest.fixture(scope="session", autouse=True)
def isolated_home():
    """Fail loudly if anything resolves outside the sandbox, or if the
    real installation's files changed during the run."""
    try:
        from PyQt6 import QtCore
        from opensnitch.utils import xdg
    except ImportError:
        # tests that run without Qt: only the check of the real files applies
        pass
    else:
        settings_file = QtCore.QSettings("opensnitch", "settings").fileName()
        for path in (settings_file, xdg.xdg_config_home, xdg.xdg_runtime_dir, xdg.Autostart().userAutostart):
            assert path.startswith(_SANDBOX + os.sep), f"not isolated: {path} is outside {_SANDBOX}"

    before = _snapshot_real_files()
    yield _SANDBOX
    after = _snapshot_real_files()
    shutil.rmtree(_SANDBOX, ignore_errors=True)
    assert before == after, f"test run modified the real installation: {before} -> {after}"

@pytest.fixture(scope="session")
def qapp():
    """Create QApplication for the entire test session."""
    app = QtWidgets.QApplication.instance()
    if app is None:
        app = QtWidgets.QApplication([])

    # Initialize after QApplication exists
    init_test_environment()

    yield app

@pytest.fixture
def qtbot(qapp, qtbot):
    """Override qtbot to ensure qapp fixture runs first."""
    return qtbot

@pytest.fixture(autouse=True)
def mock_message_dialogs():
    """Mock Message.ok() to prevent modal dialogs from blocking tests."""
    with patch('opensnitch.utils.Message.ok') as mock_ok:
        mock_ok.return_value = None
        yield mock_ok

@pytest.fixture(autouse=True)
def reset_node_before_each_test(qapp):
    """Reset node to clean state before each test for proper isolation."""
    from opensnitch.nodes import Nodes
    from opensnitch.config import Config
    from tests.dialogs import ClientConfig

    nodes = Nodes.instance()
    nodes._nodes["unix:/tmp/osui.sock"] = {
        'data': ClientConfig,
        'notifications': Queue(),
        'online': True
    }
    # Reset rules duration filter to prevent rules from being ignored
    Config.RULES_DURATION_FILTER = []
    yield
