"""Fixed authority collector, invoked by the runtime only inside the build sandbox.

Docker's archive API does not expose live tmpfs contents. This reader returns raw
untrusted file bytes, never an identity, manifest, status or filename supplied by
the project. The controller validates runtime completion and hashes those bytes.
"""
import os
import stat

if os.getuid() != 10002 or os.getgid() != 10002:
    raise RuntimeError('collector identity mismatch')

parent = os.open('/output', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    if os.listdir(parent) != ['artifact']:
        raise RuntimeError('expected exactly one output')
    descriptor = os.open('artifact', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(descriptor, 'rb') as artifact:
        before = os.fstat(artifact.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 64 * 1024 * 1024:
            raise RuntimeError('unsupported artifact')

        remaining = before.st_size
        while remaining:
            chunk = artifact.read(min(remaining, 65536))
            if not chunk:
                raise RuntimeError('short artifact')
            remaining -= len(chunk)
            while chunk:
                written = os.write(1, chunk)
                chunk = chunk[written:]
        if artifact.read(1):
            raise RuntimeError('artifact grew')

        after = os.fstat(artifact.fileno())
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after) or os.listdir(parent) != ['artifact']:
            raise RuntimeError('artifact changed during collection')
finally:
    os.close(parent)
