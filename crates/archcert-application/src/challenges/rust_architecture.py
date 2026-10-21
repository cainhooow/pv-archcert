"""Authority-owned bounded dependency guard; executed only in rootless OCI.

Repository scripts/tests are never the guard implementation. Cargo metadata is
untrusted structural input, not proof of arbitrary source behavior. This checks
named Rust layer dependency closures and source mount immutability only.
"""
import json
import os
from pathlib import Path
import resource
import subprocess
import sys

MAX_BYTES = 16 * 1024 * 1024
MAX_PACKAGES = 10000
MAX_EDGES = 100000
FORBIDDEN = ('prost', 'tonic', 'sqlx', 'diesel', 'axum', 'reqwest', 'async-openai',
             'openai', 'anthropic', 'rig-core', 'genai', 'llm', 'ollama-rs')
SIGNING = ('ed25519-dalek', 'ring', 'openssl', 'cryptoki', 'aws-sdk-kms',
           'archcert-crypto', 'archcert-certificate')


def matches(name, prefixes):
    return any(name == prefix or name.startswith(prefix + '-') for prefix in prefixes)


def check(metadata):
    packages = metadata['packages']
    nodes = metadata['resolve']['nodes']
    if len(packages) > MAX_PACKAGES or len(nodes) > MAX_PACKAGES:
        raise ValueError('package limit')
    names = {p['id']: p['name'] for p in packages}
    if len(names) != len(packages) or len(names) != len(nodes):
        raise ValueError('ambiguous metadata')
    graph = {n['id']: n['dependencies'] for n in nodes}
    if len(graph) != len(nodes) or sum(map(len, graph.values())) > MAX_EDGES:
        raise ValueError('edge limit')
    members = set(metadata['workspace_members'])
    if not members or not members <= names.keys():
        raise ValueError('workspace unavailable')
    checked = 0
    for root in sorted(members):
        name = names[root]
        core = name.endswith(('-domain', '-application'))
        semantic = name.endswith('-semantic')
        if not core and not semantic:
            continue
        seen, pending = set(), list(graph[root])
        while pending:
            dependency = pending.pop()
            if dependency in seen:
                continue
            seen.add(dependency)
            dependency_name = names[dependency]
            if matches(dependency_name, SIGNING) or (core and matches(dependency_name, FORBIDDEN)):
                raise ValueError('forbidden inward dependency: ' + name + ' -> ' + dependency_name)
            pending.extend(graph[dependency])
        checked += 1
    return checked


def main():
    if sys.argv[1:] != ['1']:
        raise ValueError('fixed bounded repetition required')
    # /source is independently verified by the runner. Even the sandbox user
    # must not be able to create authority-looking state there.
    try:
        fd = os.open('/source/.archcert-authority-write-probe', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError as error:
        if error.errno not in (13, 30):
            raise
    else:
        os.close(fd)
        raise ValueError('source mount writable')
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_BYTES, MAX_BYTES))
    with open('/work/authority-metadata.json', 'w+b') as output:
        result = subprocess.run(['cargo', 'metadata', '--offline', '--locked', '--all-features', '--format-version', '1',
                                 '--manifest-path', '/source/Cargo.toml'], stdout=output, stderr=subprocess.DEVNULL,
                                cwd='/source', timeout=120, check=False)
        if result.returncode:
            raise ValueError('metadata command failed')
        output.seek(0)
        data = output.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError('metadata byte limit')
    checked = check(json.loads(data))
    print(json.dumps(dict(challenge='rust-inward-architecture-v1', result='PASS', checked_named_layers=checked,
                          source_mount='READ_ONLY', scope='bounded Cargo dependency closure; no universal source proof'), sort_keys=True))


if __name__ == '__main__':
    main()
