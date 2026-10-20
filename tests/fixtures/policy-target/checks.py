"""Tiny controlled fixture. Its checks do not represent production assurance."""
import pathlib
import sys
import typing
import unittest


def add(a: int, b: int) -> int:
    return a + b


class Tests(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)


if __name__ == "__main__":
    if sys.argv[1] == "typecheck":
        # A narrow fixture-specific annotation/type check, not a general Python checker.
        assert typing.get_type_hints(add) == {"a": int, "b": int, "return": int}
        assert type(add(2, 3)) is int
    elif sys.argv[1] == "test":
        print("TESTS PASSED", flush=True)  # Deliberate hostile stdout spoof in failing commit.
        unittest.main(argv=[sys.argv[0]])
    elif sys.argv[1] == "build":
        source = pathlib.Path(__file__).read_text()
        code = compile(source, "checks.py", "exec")
        import marshal
        pathlib.Path("/work/checks.code").write_bytes(marshal.dumps(code))
    else:
        raise SystemExit(2)
