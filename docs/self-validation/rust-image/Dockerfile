# Build only as trusted authority provisioning, never from target-supplied recipe.
# Context requires explicit reviewed cache/advisory inputs, as documented in README.
FROM rust@sha256:16113eb5d5c1e25d9359f40115225ce8719997fb0d9a3dab83e921da0308992f
RUN apt-get update && apt-get install -y --no-install-recommends python3 git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN rustup component add rustfmt clippy \
    && CARGO_BUILD_JOBS=2 cargo install cargo-deny --version 0.20.2 --locked
COPY public-cargo-cache.tar.gz /opt/archcert/public-cargo-cache.tar.gz
RUN mkdir -p /opt/archcert/cargo \
    && tar -xzf /opt/archcert/public-cargo-cache.tar.gz -C /opt/archcert/cargo \
    && chmod -R a+rX /opt/archcert/cargo \
    && rm /opt/archcert/public-cargo-cache.tar.gz
COPY cargo /usr/local/bin/cargo
RUN chmod 755 /usr/local/bin/cargo
# The unchanged runner supplies a cleared environment, env -i, uid and tmpfs.
# No runtime socket, credential, signing key or target source is installed.
