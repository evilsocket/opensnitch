#
# pytest -v tests/test_proto_imports.py
#
# The generated protobuf code must be loaded with opensnitch.proto.import_(),
# which picks the variant that works with the installed protobuf version
# (proto.pre3200 for protobuf < 3.20). A direct import fails there.
#

import ast
import pathlib

# not used here, but the autouse fixtures of conftest.py need the modules
# loaded in this order when this file runs alone (as in test_nodes.py).
import opensnitch.proto  # noqa: F401

# static check: scan the sources, don't import them
PKG_DIR = pathlib.Path(__file__).resolve().parents[1] / "opensnitch"
GENERATED = ("ui_pb2", "ui_pb2_grpc")


def _direct_imports(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module + "." + a.name for a in node.names]
        elif isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        else:
            continue
        for name in names:
            if name.split(".")[-1] in GENERATED:
                yield node.lineno, name


def test_generated_code_loaded_with_import_():
    found = []
    for path in sorted(PKG_DIR.rglob("*.py")):
        rel = path.relative_to(PKG_DIR)
        if rel.parts[0] == "proto":
            continue
        found += [f"{rel}:{lineno} imports {name}" for lineno, name in _direct_imports(path)]
    assert found == [], "use opensnitch.proto.import_() instead:\n" + "\n".join(found)
