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
elif mode in ("timeout", "children", "double-fork"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if mode == "children":
        child = os.fork()
        if child == 0:
            os.setsid()
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            Path("/work/child.pid").write_text(str(os.getpid()))
    if mode == "double-fork":
        child = os.fork()
        if child == 0:
            os.setsid()
            if os.fork() != 0:
                os._exit(0)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        else:
            os.waitpid(child, 0)
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
    for path in ["/var/run/docker.sock", "/run/docker.sock",
                 "/run/containerd/containerd.sock", "/run/podman/podman.sock",
                 "/run/crio/crio.sock", "/run/cri-dockerd.sock",
                 "/run/k3s/containerd/containerd.sock",
                 *map(str, Path("/run/user").glob("*/docker.sock")),
                 *map(str, Path("/run/user").glob("*/podman/podman.sock"))]:
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
    for address, port in [("169.254.169.254", 80), ("169.254.170.2", 80),
                          ("100.100.100.200", 80), ("192.168.5.2", 80),
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
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
            try:
                datagram.sendto(b"archcert-denied", (address, 53))
            except OSError as error:
                assert error.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH), (address, repr(error))
            else:
                raise AssertionError("UDP route available: " + address)
    for url in ["http://169.254.169.254/latest/meta-data/", "http://192.168.5.2:18080/marker"]:
        try:
            urllib.request.urlopen(url, timeout=0.25)
        except urllib.error.URLError as error:
            assert error.reason.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH), repr(error)
        else:
            raise AssertionError("HTTP escape: " + url)
    assert set(os.listdir("/sys/class/net")) == {"lo"}
    print("network-blocked")
elif mode == "ipv6":
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError as error:
        assert error.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT), repr(error)
        print(json.dumps({"ipv6_socket": "unavailable", "errno": error.errno}))
    else:
        probe.close()
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            for address, scope in [("2001:db8::1", 0), ("fd00:ec2::254", 0),
                                   ("fe80::1", socket.if_nametoindex("lo"))]:
                with socket.socket(socket.AF_INET6, kind) as connection:
                    connection.settimeout(0.25)
                    try:
                        endpoint = (address, 80, 0, scope)
                        if kind == socket.SOCK_STREAM:
                            connection.connect(endpoint)
                        else:
                            connection.sendto(b"archcert-denied", endpoint)
                    except OSError as error:
                        assert error.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH), (address, repr(error))
                    else:
                        raise AssertionError("IPv6 route available: " + address)
        addresses = Path("/proc/net/if_inet6")
        disabled = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        print(json.dumps({"ipv6_socket": "available", "external_routes": "denied",
                          "addresses": addresses.read_text() if addresses.exists() else None,
                          "disabled": disabled.read_text().strip() if disabled.exists() else None}))
elif mode == "loopback":
    # A positive local exchange documents the network namespace's remaining path.
    with socket.socket() as listener, socket.socket() as client:
        listener.settimeout(1)
        client.settimeout(1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        client.connect(listener.getsockname())
        accepted, _ = listener.accept()
        with accepted:
            accepted.settimeout(1)
            client.sendall(b"local")
            assert accepted.recv(5) == b"local"
    ipv6 = "available"
    try:
        with socket.socket(socket.AF_INET6) as listener, socket.socket(socket.AF_INET6) as client:
            listener.settimeout(1)
            client.settimeout(1)
            listener.bind(("::1", 0))
            listener.listen(1)
            client.connect(listener.getsockname())
            accepted, _ = listener.accept()
            with accepted:
                accepted.settimeout(1)
                client.sendall(b"local")
                assert accepted.recv(5) == b"local"
    except OSError as error:
        assert error.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT,
                               errno.EADDRNOTAVAIL, errno.ENETUNREACH), repr(error)
        ipv6 = "unavailable:" + str(error.errno)
    print(json.dumps({"ipv4_loopback": "available", "ipv6_loopback": ipv6}))
elif mode == "process":
    assert os.getuid() == 10001 and os.getgid() == 10001
    assert set(os.getgroups()) <= {10001}, os.getgroups()
    processes = [int(p.name) for p in Path("/proc").iterdir() if p.name.isdigit()]
    assert processes == [1], processes
    status = Path("/proc/self/status").read_text()
    for capability in ("CapEff", "CapPrm", "CapBnd"):
        assert capability + ":\t0000000000000000" in status, status
    assert "NoNewPrivs:\t1" in status
    assert "Seccomp:\t2" in status
    assert b"archcert-host-only-process-marker" not in Path("/proc/1/cmdline").read_bytes()
    for pid in sys.argv[2:]:
        assert not Path("/proc/" + pid).exists()
    print("process-isolated")
    uid_map = Path("/proc/self/uid_map").read_text()
    gid_map = Path("/proc/self/gid_map").read_text()
    # A full identity mapping would contradict the expected rootless boundary.
    for mapping in (uid_map, gid_map):
        rows = [list(map(int, row.split())) for row in mapping.splitlines()]
        assert rows and [0, 0, 4294967295] not in rows, mapping
    try:
        security_label = Path("/proc/self/attr/current").read_text().strip()
    except OSError as error:
        security_label = "NOT_OBSERVED:errno=" + str(error.errno)
    print(json.dumps({"uid_map": uid_map, "gid_map": gid_map,
                      "groups": os.getgroups(), "security_label": security_label}))
    for action in (lambda: os.setuid(0), lambda: os.setgid(0)):
        try:
            action()
        except OSError as error:
            assert error.errno == errno.EPERM, error
        else:
            raise AssertionError("privileged identity obtained")
elif mode == "resources":
    assert Path("/sys/fs/cgroup/memory.max").read_text().strip() == sys.argv[2]
    assert Path("/sys/fs/cgroup/pids.max").read_text().strip() == sys.argv[3]
    assert Path("/sys/fs/cgroup/cpu.max").read_text().strip() == "100000 100000"
    assert Path("/sys/fs/cgroup/memory.swap.max").read_text().strip() == "0"
    print("resources-enforced")
elif mode == "disk":
    directory = sys.argv[2] if len(sys.argv) > 2 else "/work"
    assert directory in ("/work", "/tmp", "/output", "/home/archcert")
    try:
        with open(directory + "/fill", "wb") as target:
            for _ in range(100):
                target.write(b"d" * 1024 * 1024)
    except OSError as error:
        assert error.errno == errno.ENOSPC, error
        print("disk-limit-blocked")
    else:
        raise AssertionError("scratch disk not bounded")
elif mode == "cpu-throttling":
    def cpu_stat():
        return dict((key, int(value)) for key, value in
                    (line.split() for line in Path("/sys/fs/cgroup/cpu.stat").read_text().splitlines()))
    assert Path("/sys/fs/cgroup/cpu.max").read_text().strip() == "10000 100000"
    before = cpu_stat()
    started = time.process_time()
    while time.process_time() - started < 0.4:
        pass
    after = cpu_stat()
    assert after["nr_throttled"] > before["nr_throttled"], (before, after)
    assert after["throttled_usec"] > before["throttled_usec"], (before, after)
    print(json.dumps({"before": before, "after": after}))
elif mode == "process-churn":
    assert Path("/sys/fs/cgroup/pids.max").read_text().strip() == "16"
    for _ in range(100):
        child = os.fork()
        if child == 0:
            os.execl("/bin/sh", "sh", "-c", "sh -c 'sh -c true'")
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0, status
    print("bounded-process-churn")
elif mode == "cwd":
    assert os.getcwd() == sys.argv[2]
    print(os.getcwd())
else:
    raise AssertionError(mode)
