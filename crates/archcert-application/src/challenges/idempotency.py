# Authority-owned controlled idempotency replay. This code is delivered as literal
# argv to the existing isolated runner; it is never executed on the authority host.
import importlib.util
import sqlite3
import sys

repetitions = int(sys.argv[1])
if not 2 <= repetitions <= 8:
    raise ValueError("authority replay count outside template bounds")
database = "/work/ironcrest-ledger.sqlite3"
with sqlite3.connect(database) as connection:
    connection.execute("CREATE TABLE ledger (key TEXT NOT NULL, amount INTEGER NOT NULL)")
spec = importlib.util.spec_from_file_location("ironcrest_target", "/source/settlement.py")
if spec is None or spec.loader is None:
    raise RuntimeError("controlled settlement module unavailable")
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)
for _ in range(repetitions):
    target.settle(database, "authority-order-17", 7)
with sqlite3.connect(database) as connection:
    final_state = connection.execute(
        "SELECT count(*), coalesce(sum(amount), 0) FROM ledger WHERE key = ?",
        ("authority-order-17",),
    ).fetchone()
if final_state != (1, 7):
    raise AssertionError("controlled replay violated final ledger cardinality or amount")
