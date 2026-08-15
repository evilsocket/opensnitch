# conftest.py - pytest configuration for the opensnitch-cli tests
#
# opensnitch-cli runs on servers without Qt, so its tests must not need a
# QApplication. The autouse fixtures of the parent conftest.py are replaced
# here by ones that do nothing: pytest resolves fixtures from the closest
# conftest, so the GUI tests keep using the originals.

import pytest

from opensnitch.cli.config import Config
from opensnitch.cli import db as dbmod


@pytest.fixture(autouse=True)
def mock_message_dialogs():
    """the GUI's modal dialogs don't exist here."""
    yield None


@pytest.fixture(autouse=True)
def reset_node_before_each_test():
    """no Nodes singleton and no QApplication in the CLI."""
    yield None


@pytest.fixture
def config(tmp_path):
    """a configuration pointing at a throw away database."""
    path = tmp_path / "cli.conf"
    path.write_text("[db]\npath = %s\n" % (tmp_path / "cli.db"))
    return Config(path=str(path))


@pytest.fixture
def db(config):
    database = dbmod.Database(config.db_path())
    yield database
    database.close()


@pytest.fixture
def connection():
    from opensnitch.cli.proto import ui_pb2

    return ui_pb2.Connection(
        protocol="tcp", dst_ip="140.82.121.6", dst_host="api.github.com", dst_port=443,
        user_id=1000, process_id=41233, process_path="/usr/bin/curl",
        process_args=["/usr/bin/curl", "-sSL", "https://api.github.com/repos"])
