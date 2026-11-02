#!/usr/bin/python3
"""Trusted runtime simulator. Never executes the requested target command."""
import json
import os
from pathlib import Path
import sys
import time

root = Path(sys.argv[sys.argv.index("--config") + 1])
args = sys.argv[5:]
config = json.loads((root / "config.json").read_text())

with open(root / "calls.jsonl", "a") as calls:
    calls.write(json.dumps(args) + "\n")

mode = config.get("mock_mode", "removed")

if mode == "disconnected":
    sys.exit(1)

if args[0] == "info":
    print(json.dumps(config["info"]))
elif args[0] == "version":
    print(
        json.dumps(
            {
                "Client": {"Version": "test-client"},
                "Server": {
                    "Version": "test",
                    "Components": [{"Name": "runc", "Version": "test-runtime"}],
                },
            }
        )
    )
elif args[0] == "mock-env":
    print(json.dumps(dict(os.environ)))
elif args[0] == "mock-output":
    os.write(1, b"a" * 16000)
    os.write(2, b"b" * 17000)
    sys.exit(7)
elif args[0] == "mock-hang":
    time.sleep(60)
elif args[:2] in (["container", "rm"], ["image", "rm"]):
    if mode in ("absent", "cleanup-failure"):
        sys.exit(1)

    print("removed")
elif args[:2] in (["container", "ls"], ["image", "ls"]):
    if mode == "cleanup-failure":
        print("orphan-still-exists")
else:
    sys.exit(2)
