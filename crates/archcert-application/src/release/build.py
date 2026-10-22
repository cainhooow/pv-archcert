"""Authority-owned offline Rust recipe, executed only inside the isolated runner."""
import json
import os
import signal
import stat
import subprocess
import sys
import time

binary = sys.argv[1]
os.environ.update(json.loads(sys.argv[2]))
os.makedirs('/home/archcert/.cargo', mode=0o700, exist_ok=True)
os.symlink('/opt/archcert/cargo/registry', '/home/archcert/.cargo/registry')

# No repository-provided shell or launcher. Cargo still executes hostile build
# scripts, rustc wrappers and source under the ordinary sandbox boundary.
status = subprocess.run(
    [
        '/usr/local/cargo/bin/cargo', 'build', '--release', '--locked', '--offline',
        '--target', 'x86_64-unknown-linux-gnu', '--bin', binary,
    ],
    cwd='/source',
    stdin=subprocess.DEVNULL,
    stdout=sys.stderr,
    stderr=sys.stderr,
    check=False,
).returncode
if status != 0:
    sys.exit(status if status > 0 else 1)

# Traverse each component without following links. The runner subsequently freezes
# the whole sandbox and validates its own archive copy; this launcher cannot assert
# authority over either the accepted digest or the reproducibility verdict.
parent = os.open('/work', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    for component in ['target', 'x86_64-unknown-linux-gnu', 'release']:
        child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        os.close(parent)
        parent = child

    descriptor = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(descriptor, 'rb') as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError('unsupported output type')
        if not 0 < metadata.st_size <= 64 * 1024 * 1024:
            raise RuntimeError('output size limit')

        with open('/output/artifact', 'xb') as output:
            remaining = metadata.st_size
            while remaining:
                chunk = source.read(min(remaining, 65536))
                if not chunk:
                    raise RuntimeError('short output')
                output.write(chunk)
                remaining -= len(chunk)
            if source.read(1):
                raise RuntimeError('output grew')
finally:
    os.close(parent)

# The separate unprivileged authority reader must be able to traverse this mount.
# Target descendants remain UID 10001 and cannot access the reader's UID 10002 FDs.
os.chmod('/output/artifact', 0o444)
os.chmod('/output', 0o755)

# Install the completion handshake before publishing readiness. Only the authority
# runtime controls the collection/completion boundary; the marker grants no verdict.
released = False


def release(_signal, _frame):
    global released
    released = True


signal.signal(signal.SIGUSR1, release)
os.write(1, b'ARCHCERT_BUILD_READY_V1\n')
while not released:
    time.sleep(0.01)
