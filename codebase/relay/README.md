# SafeChat Relay

`safechat-relay` is an independent HTTPS/WebSocket relay. It does not depend
on the SafeChat client crate, UI, client profile, or client database.

## Build

From `codebase/`:

```sh
cargo build --release --locked -p safechat-relay
```

## Allowlist a client

The administrator needs the client's Base64 identity key, fingerprint, client
ID, and one-time enrollment secret:

```sh
safechat-relay allowlist-add \
  --database relay.db \
  --client-id <client-id> \
  --identity-key <url-safe-base64-identity-key> \
  --fingerprint <fingerprint> \
  --enrollment-secret <one-time-secret>
```

The client then calls `/v1/devices/challenge`, signs the returned challenge
with its identity key, and calls `/v1/devices/register` to receive an access
token.

Revoke a client and invalidate its active session:

```sh
safechat-relay allowlist-revoke \
  --database relay.db \
  --client-id <client-id>
```

## Run with native TLS

```sh
safechat-relay serve \
  --database relay.db \
  --tls-cert /etc/safechat-relay/tls/fullchain.pem \
  --tls-key /etc/safechat-relay/tls/privkey.pem
```

The container image is defined in `Dockerfile`. Mount the database and TLS
directory as external volumes; do not put private TLS keys in the image.
