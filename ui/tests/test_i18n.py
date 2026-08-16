import ast
from pathlib import Path


def _contains_runtime_interpolation(node):
    for child in ast.walk(node):
        if isinstance(child, ast.JoinedStr):
            return True
        if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Mod):
            return True
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr == "format"
        ):
            return True
    return False


def test_translation_lookup_happens_before_runtime_interpolation():
    source_root = Path(__file__).resolve().parents[1] / "opensnitch"
    failures = []

    for source_path in sorted(source_root.rglob("*.py")):
        tree = ast.parse(
            source_path.read_text(encoding="utf-8"),
            filename=str(source_path),
        )
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"translate", "translated"}
                and len(node.args) > 1
            ):
                continue
            if _contains_runtime_interpolation(node.args[1]):
                failures.append(f"{source_path.relative_to(source_root)}:{node.lineno}")

    assert not failures, (
        "Translate the static source string before inserting runtime values:\n"
        + "\n".join(failures)
    )
