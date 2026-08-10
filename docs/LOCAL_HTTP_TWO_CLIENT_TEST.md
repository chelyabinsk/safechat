# Local HTTP relay test with two SafeChat clients

This runbook starts one disposable HTTP relay and two real SafeChat UI
clients. It verifies enrollment, administrator approval, fingerprint
confirmation, private-lobby creation, and encrypted messages in both
directions.

Use this only on a private local machine. HTTP exposes credentials and relay
metadata to local-network observers; message contents remain end-to-end
encrypted.

Run all commands from the repository root. Use separate terminals for the
relay, Alice, Bob, and administrator commands.

## 1. Build the Docker images

The development image is built from the repository root. The standalone relay
image must use `codebase/` as its build context; using the repository root can
send unrelated local files into the Docker build.

```bash
docker compose build rust-dev
docker build -t safechat-relay:local -f codebase/relay/Dockerfile codebase
```

Create the Compose network before starting the relay container:

```bash
docker compose run --rm rust-dev true
```

## 2. Create disposable test state

```bash
export TEST_ROOT=/tmp/safechat-local-http-test
rm -rf "$TEST_ROOT"
mkdir -p "$TEST_ROOT/alice" "$TEST_ROOT/bob"
chmod 700 "$TEST_ROOT" "$TEST_ROOT/alice" "$TEST_ROOT/bob"
docker rm -f safechat-local-relay 2>/dev/null || true
docker volume rm safechat-local-relay-data 2>/dev/null || true
docker volume create safechat-local-relay-data
openssl rand -hex 32 > "$TEST_ROOT/admin-token"
export RELAY_ADMIN_TOKEN="$(cat "$TEST_ROOT/admin-token")"
```

## 3. Start the relay

```bash
docker run -d \
  --name safechat-local-relay \
  --network safechat_default \
  -p 127.0.0.1:18081:8080 \
  -e SAFECHAT_RELAY_ADMIN_TOKEN="$RELAY_ADMIN_TOKEN" \
  -v safechat-local-relay-data:/var/lib/safechat-relay \
  safechat-relay:local serve \
  --http \
  --bind 0.0.0.0:8080 \
  --database /var/lib/safechat-relay/relay.db \
  --admin-token "$RELAY_ADMIN_TOKEN"
```

Check the relay from the host:

```bash
for attempt in {1..30}; do
  curl -fsS http://127.0.0.1:18081/v1/health && break
  sleep 1
done
```

Expected response:

```json
{"api_version":"safechat-relay-v1","status":"ok"}
```

Check it from the Docker network too:

```bash
docker compose run --rm rust-dev \
  bash -lc 'curl -fsS http://safechat-local-relay:8080/v1/health'
```

## 4. Start Alice

In a new terminal:

```bash
export TEST_ROOT=/tmp/safechat-local-http-test
docker compose run --rm \
  -v "$TEST_ROOT/alice:/tmp/safechat-local-alice:Z" \
  rust-dev cargo run --locked --bin safechat-ui -- \
  --profile local-alice \
  --data-dir /tmp/safechat-local-alice \
  --relay-url http://safechat-local-relay:8080
```

When prompted:

1. Create and confirm a profile password.
2. Initialize the profile.
3. Enter a display name such as `Alice`.
4. Select `Relay`.
5. Confirm the HTTP warning.
Leave Alice waiting for administrator approval. The relay will display a
server-assigned client ID after accepting the enrollment request.

## 5. Start Bob

In another new terminal:

```bash
export TEST_ROOT=/tmp/safechat-local-http-test
docker compose run --rm \
  -v "$TEST_ROOT/bob:/tmp/safechat-local-bob:Z" \
  rust-dev cargo run --locked --bin safechat-ui -- \
  --profile local-bob \
  --data-dir /tmp/safechat-local-bob \
  --relay-url http://safechat-local-relay:8080
```

Complete the same prompts for Bob and leave him waiting for approval. No CA
certificate prompt is shown for an `http://` relay.

## 6. Inspect and approve enrollment requests

Run these commands from a separate administrator terminal, never inside an
Alice or Bob UI terminal:

```bash
docker run --rm \
  -v safechat-local-relay-data:/var/lib/safechat-relay \
  safechat-relay:local enrollment-pending \
  --database /var/lib/safechat-relay/relay.db
```

Verify the displayed fingerprints through your intended trusted channel, then
copy the server-assigned IDs into shell variables and approve requests one at a
time:

```bash
export ALICE_CLIENT_ID='SERVER_ASSIGNED_ALICE_ID'
export BOB_CLIENT_ID='SERVER_ASSIGNED_BOB_ID'
```

```bash
docker run --rm \
  -v safechat-local-relay-data:/var/lib/safechat-relay \
  safechat-relay:local enrollment-approve \
  --database /var/lib/safechat-relay/relay.db \
  --client-id "$ALICE_CLIENT_ID"
```

```bash
docker run --rm \
  -v safechat-local-relay-data:/var/lib/safechat-relay \
  safechat-relay:local enrollment-approve \
  --database /var/lib/safechat-relay/relay.db \
  --client-id "$BOB_CLIENT_ID"
```

Wait for both clients to print `Relay transport enabled`. Check that no
requests remain:

```bash
docker run --rm \
  -v safechat-local-relay-data:/var/lib/safechat-relay \
  safechat-relay:local enrollment-pending \
  --database /var/lib/safechat-relay/relay.db
```

Expected response:

```text
No pending enrollment requests.
```

## 7. Establish the private lobby

In Alice:

```text
/add-contact SERVER_ASSIGNED_BOB_ID
```

In Bob:

```text
/contacts
```

Accept Alice’s request and confirm Alice’s fingerprint. Then, in Alice, run
`/contacts`, confirm Bob’s fingerprint, and wait for both clients to report
that the private lobby is ready.

Check both clients:

```text
/peers
```

Each should list exactly one trusted private lobby.

## 8. Verify encrypted chat in both directions

In Alice, type ordinary text:

```text
hello from Alice
```

Bob should display the received message. In Bob, type:

```text
hello from Bob
```

Alice should display the reply. The sender should eventually show `[sent]`
and `[read]`.

In Alice, run:

```text
/cipher
```

The history should show `safechat-text-v1:` ciphertext rather than plaintext.
Run `/clean` to return to readable history.

## 9. Check persisted state

```bash
find "$TEST_ROOT" -type f -printf '%M %s %p\\n' | sort
```

The profiles should contain encrypted identity databases, encrypted relay
sessions, encrypted peer mappings, encrypted lobby histories, and public peer
bundles. The relay should still be healthy:

```bash
curl -fsS http://127.0.0.1:18081/v1/health
docker ps --filter name=safechat-local-relay
```

## 10. Clean up

Stop the two UI terminals with `Ctrl-C`, then run:

```bash
docker rm -f safechat-local-relay
docker volume rm safechat-local-relay-data
rm -rf /tmp/safechat-local-http-test
```

The commands above remove only the disposable test relay, volume, and
profiles.
