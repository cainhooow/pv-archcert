"""Bounded project checks for the local Python authority command contract.

The annotation check covers this module's ledger API only. It is not mypy or a
proof of general Python type safety. All checks execute only inside the runner.
"""

import marshal
from pathlib import Path
import sys
import typing
import unittest

from ledger import Entry, balance


class LedgerTests(unittest.TestCase):
    def test_credit_and_debit(self):
        self.assertEqual(balance([Entry("invoice", 1000), Entry("refund", -250)]), 750)

    def test_empty(self):
        self.assertEqual(balance([]), 0)

    def test_duplicate_is_rejected(self):
        with self.assertRaises(ValueError):
            balance([Entry("same", 100), Entry("same", 100)])

    def test_float_and_boolean_are_rejected(self):
        for amount in (1.5, True):
            with self.assertRaises(ValueError):
                Entry("invalid", amount)


if __name__ == "__main__":
    operation = sys.argv[1]
    if operation == "typecheck":
        assert typing.get_type_hints(balance) == {"entries": list[Entry], "return": int}
        assert type(balance([Entry("typed", 200)])) is int
    elif operation == "test":
        unittest.main(argv=[sys.argv[0]])
    elif operation == "build":
        source = Path(__file__).with_name("ledger.py")
        code = compile(source.read_text(), "ledger.py", "exec")
        Path("/work/ledger.code").write_bytes(marshal.dumps(code))
    else:
        raise SystemExit(2)
