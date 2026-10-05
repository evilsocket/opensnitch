#
# pytest -v tests/test_table_models.py
#

import pytest
from PyQt6 import QtCore
from PyQt6.QtSql import QSqlDatabase, QSqlQuery

from opensnitch.utils import AsnDB
from opensnitch.customwidgets.generictableview import GenericTableModel
from opensnitch.customwidgets.addresstablemodel import AddressTableModel


@pytest.fixture
def stats_db(qapp):
    db = QSqlDatabase.addDatabase("QSQLITE", "test_table_models")
    db.setDatabaseName(":memory:")
    assert db.open()
    QSqlQuery("CREATE TABLE addrs (what TEXT, hits INTEGER)", db).exec()
    QSqlQuery("INSERT INTO addrs VALUES ('1.1.1.1', 3)", db).exec()
    yield db
    db.close()
    del db
    QSqlDatabase.removeDatabase("test_table_models")


def headers(model):
    return [model.headerData(i, QtCore.Qt.Orientation.Horizontal) for i in range(model.columnCount())]


@pytest.mark.parametrize("model_class", [GenericTableModel, AddressTableModel])
@pytest.mark.parametrize("asn_available", [False, True])
def test_issue_1674_stats_headers_keep_labels(stats_db, monkeypatch, model_class, asn_available):
    """The stats tabs must show their translated headers, not the raw
    db column names, also after opening and closing a detail view."""
    monkeypatch.setattr(AsnDB.instance(), "is_available", lambda: asn_available)
    expected = ["What", "Hits"]
    if model_class is AddressTableModel and asn_available:
        expected.append("Network name")

    model = model_class("addrs", ["What", "Hits"])
    model.setQuery("SELECT * FROM addrs", stats_db)
    assert headers(model) == expected

    # detail view: same model, more columns than any list view
    model.setQuery("SELECT what as Address, hits as Hits, 'x' as Process, 0 as UID FROM addrs", stats_db)
    assert headers(model) == ["Address", "Hits", "Process", "UID"]

    model.setQuery("SELECT * FROM addrs", stats_db)
    assert headers(model) == expected
