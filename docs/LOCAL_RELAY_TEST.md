# Local relay test

This runbook starts one SafeChat relay in Docker and two local SafeChat UI
clients. New users are added through docker exec while the relay remains
running.

Run commands from the repository root.

## 1. Build

    docker compose run --rm rust-dev cargo build --release --locked

Set the admin token:

    export SAFECHAT_RELAY_ADMIN_TOKEN="$(openssl rand -hex 32)"

Keep the temporary TLS bind mount in a fresh workspace directory for this
local test:

    export SAFECHAT_RELAY_TLS_DIR="$PWD/relay-tls-local"

This host's Docker user-namespace setup maps the current host UID into the
container. Use that mapped UID for this local bind-mounted smoke test:

    export SAFECHAT_RELAY_USER="$(id -u):$(id -g)"
    export SAFECHAT_RELAY_DATA_DIR="$PWD/relay-data-local"

Build the relay image:

    docker compose -f docker-compose.relay.yml build

## 2. Prepare TLS and profiles

    docker compose -f docker-compose.relay.yml down -v
    rm -rf /tmp/safechat-alice /tmp/safechat-bob "$SAFECHAT_RELAY_TLS_DIR" "$SAFECHAT_RELAY_DATA_DIR"
    mkdir -p /tmp/safechat-alice /tmp/safechat-bob "$SAFECHAT_RELAY_TLS_DIR" "$SAFECHAT_RELAY_DATA_DIR"
    chmod 700 /tmp/safechat-alice /tmp/safechat-bob
    chmod 755 "$SAFECHAT_RELAY_TLS_DIR"

Generate a temporary local certificate:

    openssl req -x509 -newkey rsa:2048 \
      -keyout "$SAFECHAT_RELAY_TLS_DIR/privkey.pem" \
      -out "$SAFECHAT_RELAY_TLS_DIR/fullchain.pem" \
      -days 1 \
      -nodes \
      -subj /CN=127.0.0.1 \
      -addext 'basicConstraints=critical,CA:FALSE' \
      -addext 'subjectAltName=IP:127.0.0.1' \
      -addext 'extendedKeyUsage=serverAuth'

The `:Z` suffix on the compose volume allows the container to read the bind
mount on SELinux-enabled hosts. The local smoke test uses 644 for the
temporary key because the bind-mounted directory is owned by the mapped test
UID. For a real deployment, keep the default non-root service user and use a
secret/file-permission setup suitable for the host's container runtime.

The certificate must include `CA:FALSE`, the localhost IP SAN, and
`serverAuth`; a generic self-signed CA certificate is rejected by the client
as an invalid server certificate.

## 3. Start the relay

    docker compose -f docker-compose.relay.yml up -d
    docker compose -f docker-compose.relay.yml ps
    docker logs safechat-relay --tail 30

The container is named safechat-relay and listens on port 8443.

## 4. Start Alice

    ./codebase/target/release/safechat-ui \
      --profile alice \
      --data-dir /tmp/safechat-alice \
      --relay-url https://127.0.0.1:8443 \
      --relay-ca-cert "$SAFECHAT_RELAY_TLS_DIR/fullchain.pem"

Choose Relay and initialize Alice. The client generates its one-time
enrollment secret automatically. The relay assigns Alice's client ID when the
enrollment request is submitted. Copy that ID and fingerprint. Leave Alice at
the retry prompt.

## 5. Start Bob

    ./codebase/target/release/safechat-ui \
      --profile bob \
      --data-dir /tmp/safechat-bob \
      --relay-url https://127.0.0.1:8443 \
      --relay-ca-cert "$SAFECHAT_RELAY_TLS_DIR/fullchain.pem"

Choose Relay and initialize Bob. Copy the server-assigned client ID and
fingerprint, then leave Bob at the retry prompt.

## 6. Inspect and approve both enrollments

From a separate administrator terminal:

    docker exec safechat-relay \
      safechat-relay enrollment-pending \
      --database /var/lib/safechat-relay/relay.db

Review the displayed fingerprints, then approve each server-assigned ID:

    docker exec safechat-relay \
      safechat-relay enrollment-approve \
      --database /var/lib/safechat-relay/relay.db \
      --client-id 'ALICE_CLIENT_ID'

    docker exec safechat-relay \
      safechat-relay enrollment-approve \
      --database /var/lib/safechat-relay/relay.db \
      --client-id 'BOB_CLIENT_ID'

The admin token is inherited by the CLI inside the container. The relay does
not need to be restarted.

Use the exact server-assigned client IDs when adding peers. The UI may
display a peer as `Alice (Alice.1)`: `Alice` is the display name, while
`Alice.1` is the Signal identity address. The updated client handles this
mapping automatically after restart.

## 7. Complete enrollment

Return to Alice and Bob and answer Yes at the retry prompt. After both report
Relay transport enabled, each client will request the peer's relay client ID:

- Alice enters Bob's client ID.
- Bob enters Alice's client ID.

Confirm the displayed fingerprints. Check the mode with:

    /transport

It should report Transport: Relay.

## 8. Test communication

In relay mode, type ordinary text in Alice; it is sent automatically:

    hello Bob

Bob's UI checks the relay automatically and displays the message without `/r`.
Reply by typing ordinary text:

    hello Alice

Alice receives the reply automatically as well. The old `/s` and `/r` commands
remain available as explicit send and poll aliases if desired.

Manual ciphertext decryption remains available:

    /r <ciphertext>

Transport controls:

    /transport
    /transport copy
    /transport relay

## 10. Clean up

    docker compose -f docker-compose.relay.yml down
    rm -rf /tmp/safechat-alice /tmp/safechat-bob

Remove the relay test volume too with:

    docker compose -f docker-compose.relay.yml down -v
