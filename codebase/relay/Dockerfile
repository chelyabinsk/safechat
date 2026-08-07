# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS build

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        ca-certificates \
        git \
        pkg-config \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --locked -p safechat-relay

FROM debian:bookworm-slim

RUN groupadd --system --gid 10001 safechat-relay \
    && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent \
        --shell /usr/sbin/nologin safechat-relay \
    && mkdir -p /var/lib/safechat-relay /etc/safechat-relay/tls \
    && chown -R safechat-relay:safechat-relay /var/lib/safechat-relay /etc/safechat-relay

COPY --from=build /src/target/release/safechat-relay /usr/local/bin/safechat-relay

USER safechat-relay
WORKDIR /var/lib/safechat-relay
EXPOSE 8080 8443

ENTRYPOINT ["/usr/local/bin/safechat-relay"]
