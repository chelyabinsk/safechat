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

Messages are queued with `POST /v1/messages`. The recipient retrieves and
acknowledges them with `GET /v1/messages` and `POST /v1/messages/{server_id}/ack`.
The sender can query `GET /v1/messages/status?message_id=...`; the status is
`sent` until the recipient acknowledges the message, then becomes `read`.

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
  --tls-key /etc/safechat-relay/tls/privkey.pem \
  --admin-token '<high-entropy-admin-token>'
```

With `--admin-token`, allowlist entries can be added while the relay is
running through the TLS-protected administrative endpoint:

```sh
curl --fail --silent --show-error \
  --cacert /path/to/relay-ca.pem \
  -H 'Authorization: Bearer <admin-token>' \
  -H 'Content-Type: application/json' \
  --data '{"client_id":"alice","identity_key":"<public-key>","fingerprint":"<fingerprint>","enrollment_secret":"<one-time-secret>","label":"Alice"}' \
  https://relay.example/v1/admin/allowlist
```

The endpoint is disabled unless an admin token is configured. The token is
separate from client enrollment credentials and must be protected like other
server administration secrets.

The image includes a CLI wrapper for this operation. When running the
provided Compose service, add a client without stopping the container:

```sh
docker exec safechat-relay safechat-relay allowlist-add-remote \
  --url https://127.0.0.1:8443 \
  --ca-cert /etc/safechat-relay/tls/fullchain.pem \
  --client-id <client-id> \
  --identity-key <public-identity-key> \
  --fingerprint <fingerprint> \
  --enrollment-secret <one-time-secret> \
  --label <label>
```

The admin token is read from `SAFECHAT_RELAY_ADMIN_TOKEN` inside the
container. This command talks to the live HTTPS admin endpoint; it does not
open the relay database separately.

The container image is defined in `Dockerfile`. Mount the database and TLS
directory as external volumes; do not put private TLS keys in the image.
