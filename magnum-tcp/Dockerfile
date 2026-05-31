FROM rust:slim AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 curl tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/magnum-tcp /usr/local/bin/magnum-tcp
COPY test_entrypoint.sh /test_entrypoint.sh
RUN chmod +x /test_entrypoint.sh

ENTRYPOINT ["/test_entrypoint.sh"]
