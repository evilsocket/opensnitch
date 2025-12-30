# conftest.py - pytest configuration for opensnitch UI tests
#
# This file sets up Qt and database before tests run.

import pytest
from PyQt6 import QtWidgets
from unittest.mock import patch
from queue import Queue

# Global flag to track initialization
_initialized = False

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
