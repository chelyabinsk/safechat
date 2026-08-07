# SafeChat Relay

`safechat-relay` is an independent HTTP(S)/WebSocket relay. It does not depend
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

## Run behind Caddy

For a public deployment, Caddy can terminate HTTPS and renew the public
certificate automatically. Run the relay in explicit private HTTP mode:

```sh
safechat-relay serve \
  --http \
  --bind 0.0.0.0:8080 \
  --database /var/lib/safechat-relay/relay.db \
  --admin-token '<high-entropy-admin-token>'
```

Use `--http` only when the bind address is private or the process is behind a
trusted TLS reverse proxy. Do not expose this listener directly to the
Internet.

The repository's `docker-compose.relay.yml` runs this mode behind Caddy. Set
`SAFECHAT_RELAY_HOSTNAME` to the public DNS name, point that name at the VPS,
and start the stack:

```sh
export SAFECHAT_RELAY_HOSTNAME=relay.example.com
export SAFECHAT_RELAY_ADMIN_TOKEN='<high-entropy-admin-token>'
docker compose -f docker-compose.relay.yml pull
docker compose -f docker-compose.relay.yml up -d
```

Caddy publishes port 8443 for HTTPS and port 80 for ACME certificate
issuance/renewal, obtains and renews the certificate, and proxies both HTTP
API and WebSocket traffic to the private relay container. Clients use
`https://relay.example.com:8443`. The relay itself publishes no host port.

The Compose file uses the prebuilt image published at
`ghcr.io/chelyabinsk/safechat-relay:latest`; override
`SAFECHAT_RELAY_IMAGE` when using a fork or a pinned release tag.

The image includes a CLI wrapper for this operation. When running the
provided Compose service, add a client without stopping the container:

```sh
docker exec safechat-relay safechat-relay allowlist-add-remote \
  --url http://127.0.0.1:8080 \
  --allow-http \
  --client-id <client-id> \
  --identity-key <public-identity-key> \
  --fingerprint <fingerprint> \
  --enrollment-secret <one-time-secret> \
  --label <label>
```

The admin token is read from `SAFECHAT_RELAY_ADMIN_TOKEN` inside the
container. This command talks to the live admin endpoint over the relay's
private loopback HTTP listener; it does not open the relay database separately.

The container image is defined in `Dockerfile`. Mount the database as an
external volume. For native TLS deployments, also mount the TLS directory;
the Caddy deployment does not require relay certificate files.

## Run plain HTTP on a trusted network

For a private LAN, VPN, or other trusted network where HTTPS certificate
management is intentionally omitted, the relay can run in plain HTTP mode:

```sh
safechat-relay serve \
  --http \
  --bind 0.0.0.0:8080 \
  --database relay.db \
  --admin-token '<high-entropy-admin-token>'
```

Clients can then enter an `http://` relay URL and must explicitly confirm the
insecure transport warning. End-to-end message encryption still protects
message contents, but HTTP exposes relay access tokens, client identities,
metadata, and traffic patterns and permits active network interference. Never
expose this mode directly to the public Internet.
