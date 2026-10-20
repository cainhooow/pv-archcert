"""ArchCert-owned hostile code. Execute ONLY through the isolated runner."""
import errno
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error

mode = sys.argv[1]
if mode == "normal":
    print("normal stdout")
    print("normal stderr", file=sys.stderr)
elif mode == "nonzero":
    print("ARCHCERT RESULT: PASS")  # deliberately false evidence claim
    sys.exit(7)
elif mode == "binary":
    os.write(1, b"\x1b[2J\xffstdout\x00")
    os.write(2, b"\x1b]0;injection\x07\xfestderr")
elif mode == "prefix":
    os.write(1, b"a" * 16000)
    os.write(2, b"b" * 17000)
elif mode in ("stdout-flood", "stderr-flood"):
    fd = 1 if mode == "stdout-flood" else 2
    while True:
        os.write(fd, b"F" * 8192)
elif mode in ("timeout", "children"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if mode == "children":
        child = os.fork()
        if child == 0:
            os.setsid()
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            Path("/work/child.pid").write_text(str(os.getpid()))
    print(mode + "-started", flush=True)
    while True:
        pass
elif mode == "exit-with-child":
    if os.fork() == 0:
        os.setsid()
        while True:
            time.sleep(0.1)
    sys.exit(0)
elif mode == "memory":
    chunks = []
    while True:
        chunks.append(bytearray(4 * 1024 * 1024))
elif mode == "fork":
    children = []
    try:
        while True:
            pid = os.fork()
            if pid == 0:
                time.sleep(60)
                os._exit(0)
            children.append(pid)
    except OSError as error:
        assert error.errno == errno.EAGAIN, error
        assert 1 <= len(children) < 64, len(children)
        print("pid-limit-blocked", len(children), flush=True)
    finally:
        for child in children:
            os.kill(child, signal.SIGKILL)
        for child in children:
            os.waitpid(child, 0)
elif mode == "environment":
    allowed = {"PATH", "HOME", "TMPDIR", "LANG", "HOSTNAME"}
    # CPython may add LC_CTYPE during startup. It is generated in-process, not
    # inherited from the authority. Inspect environ before Python via /proc too.
    raw = Path("/proc/self/environ").read_bytes().split(b"\0")
    actual = {v.split(b"=", 1)[0].decode() for v in raw if v}
    assert actual == allowed, actual
    forbidden = ["SSH_AUTH_SOCK", "DATABASE_URL", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                 "OPENAI_API_KEY", "GITHUB_TOKEN", "NPM_TOKEN", "DOCKER_HOST", "KUBECONFIG", "ARCHCERT_TEST_HOST_SECRET"]
    assert not any(k in os.environ for k in forbidden), dict(os.environ)
    assert os.environ["HOME"] == "/home/archcert"
    assert list(Path("/home/archcert").iterdir()) == []
    print(json.dumps(dict(os.environ), sort_keys=True))
elif mode == "filesystem":
    for path in ["/source/escape", *sys.argv[2:]]:
        try:
            Path(path).read_bytes()
        except (FileNotFoundError, PermissionError, IsADirectoryError):
            pass
        else:
            raise AssertionError("host-only file visible: " + path)
    for path in ["/source/accepted.txt", "/source/hostile.py", "/source/new", "/etc/archcert-escape", "/outside"]:
        try:
            Path(path).write_text("mutated")
        except OSError:
            pass
        else:
            raise AssertionError("unexpected write: " + path)
    assert Path("/source/accepted.txt").read_bytes() == b"accepted bytes\n"
    for path in ["/work/a", "/output/a", "/tmp/a", "/home/archcert/a"]:
        Path(path).write_text("scratch")
    for path in ["/var/run/docker.sock", "/run/docker.sock", "/run/user/501/docker.sock"]:
        assert not Path(path).exists(), path
    print("filesystem-blocked")
elif mode == "network":
    # DNS must fail independently of public network availability. This name has
    # no hosts-file entry. All numeric probes require a non-loopback route.
    try:
        socket.setdefaulttimeout(0.25)
        socket.getaddrinfo("archcert-denied.invalid", 80)
    except OSError:
        pass
    else:
        raise AssertionError("DNS unexpectedly succeeded")
    for address, port in [("169.254.169.254", 80), ("192.168.5.2", 80),
                          ("10.0.2.2", 80), ("172.17.0.1", 80), ("192.0.2.1", 8080)]:
        connection = socket.socket()
        connection.settimeout(0.25)
        try:
            connection.connect((address, port))
            connection.sendall(b"GET / HTTP/1.0\r\n\r\n")
        except OSError as error:
            # ENETUNREACH is decisive: no external network route exists, even
            # when the tested endpoint has no listening service.
            assert error.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH), (address, repr(error))
        else:
            raise AssertionError("network escape: " + address)
        finally:
            connection.close()
    for url in ["http://169.254.169.254/latest/meta-data/", "http://192.168.5.2:18080/marker"]:
        try:
            urllib.request.urlopen(url, timeout=0.25)
        except urllib.error.URLError as error:
            assert error.reason.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH), repr(error)
        else:
            raise AssertionError("HTTP escape: " + url)
    assert set(os.listdir("/sys/class/net")) == {"lo"}
    print("network-blocked")
elif mode == "process":
    assert os.getuid() == 10001 and os.getgid() == 10001
    processes = [int(p.name) for p in Path("/proc").iterdir() if p.name.isdigit()]
    assert processes == [1], processes
    status = Path("/proc/self/status").read_text()
    assert "CapEff:\t0000000000000000" in status
    assert "NoNewPrivs:\t1" in status
    assert "Seccomp:\t2" in status
    assert b"archcert-host-only-process-marker" not in Path("/proc/1/cmdline").read_bytes()
    for pid in sys.argv[2:]:
        assert not Path("/proc/" + pid).exists()
    print("process-isolated")
elif mode == "resources":
    assert Path("/sys/fs/cgroup/memory.max").read_text().strip() == sys.argv[2]
    assert Path("/sys/fs/cgroup/pids.max").read_text().strip() == sys.argv[3]
    assert Path("/sys/fs/cgroup/cpu.max").read_text().strip() == "100000 100000"
    assert Path("/sys/fs/cgroup/memory.swap.max").read_text().strip() == "0"
    print("resources-enforced")
elif mode == "disk":
    try:
        with open("/work/fill", "wb") as target:
            for _ in range(100):
                target.write(b"d" * 1024 * 1024)
    except OSError as error:
        assert error.errno == errno.ENOSPC, error
        print("disk-limit-blocked")
    else:
        raise AssertionError("scratch disk not bounded")
elif mode == "cwd":
    assert os.getcwd() == sys.argv[2]
    print(os.getcwd())
else:
    raise AssertionError(mode)
