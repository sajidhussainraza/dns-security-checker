"""Minimal stdlib test runner (pytest is not installed here).

Run: python3 tests/run_tests.py
Calls every test_* function in test_dns_security_checker.py, passing a
tiny monkeypatch object to functions that take one argument.
"""

import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_dns_security_checker as t


class MonkeyPatch:
    def __init__(self):
        self._saved = []

    def setattr(self, target, name, value):
        obj = target if isinstance(target, type) else target
        if isinstance(target, str):
            raise TypeError("pass the module object, not its name")
        self._saved.append((target, name, getattr(target, name)))
        setattr(target, name, value)

    def undo(self):
        for target, name, old in reversed(self._saved):
            setattr(target, name, old)
        self._saved.clear()


def main():
    passed = failed = 0
    for name, func in sorted(inspect.getmembers(t, inspect.isfunction)):
        if not name.startswith("test_"):
            continue
        patch = MonkeyPatch()
        try:
            if len(inspect.signature(func).parameters) == 1:
                func(patch)
            else:
                func()
            patch.undo()
            print("PASS %s" % name)
            passed += 1
        except Exception as exc:  # noqa: BLE001 - report any failure
            patch.undo()
            print("FAIL %s: %s: %s" % (name, type(exc).__name__, exc))
            failed += 1
    print("\n%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
