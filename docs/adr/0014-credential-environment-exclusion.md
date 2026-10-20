# ADR-0014: Constructed environment and credential exclusion

Status: Accepted for Milestone 3.

Target environment is fixed PATH=/usr/local/bin:/usr/bin:/bin,
HOME=/home/archcert, TMPDIR=/tmp, LANG=C.UTF-8 and HOSTNAME=archcert. Target input
cannot add environment variables. HOME is an initially empty bounded private
tmpfs. No host HOME, SSH agent, Git config, cloud config, shell history or package
credential files are copied. Host secrets, including SSH_AUTH_SOCK, DATABASE_URL,
OPENAI_API_KEY, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, NPM_TOKEN,
DOCKER_HOST and KUBECONFIG, never pass through the client environment or mounts.

Image ENV values outside this allowlist are explicitly removed. Docker represents
these deletions as valueless KEY tombstones in Config.Env; stopped-container
inspection rejects unexpected KEY=value entries. The trusted image's /usr/bin/env
-i then constructs the exact target environment and execs literal program/argv.
The wrapper does no shell parsing. Language runtimes may subsequently add their
own values (e.g. Python locale coercion); this is target behavior, not credential
inheritance. Evidence records authority-exposed keys.

A fresh mode-private Docker config prevents accidental CLI proxy/registry auth
injection. Runtime errors do not print raw daemon diagnostics. Canary tests poison
only isolated harness subprocess environments; no unsafe process-wide set_var is
needed. Broad secret redaction is deferred: the primary defense is exclusion.
Tracked source can itself contain secrets; ArchCert does not rewrite accepted
source or promise to remove project-authored secrets from hostile output.
