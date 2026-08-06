# Signal protocol integration

SafeChat uses the official Signal `libsignal-protocol` crate as the protocol implementation. SafeChat owns only the application boundary around it:

```text
libsignal session state and cryptography
        ↓
SafeChat protocol adapter
        ↓
carrier-independent envelope
        ↓
VK, text, image, GIF, audio, or video transport
```

The dependency is pinned by an exact upstream Git revision in `codebase/Cargo.toml`. Do not import `libsignal-protocol` directly from application commands; all integration code belongs in `codebase/src/signal_adapter.rs` and its future submodules.

## Update procedure

1. Fetch the upstream repository and inspect release notes, protocol changes, license changes, and required toolchain changes.
2. Select a specific upstream commit; never change the dependency to an unpinned branch or floating tag.
3. Update both the `rev` in `codebase/Cargo.toml` and `LIBSIGNAL_REVISION` in `codebase/src/signal_adapter.rs`.
4. Run `cargo update -p libsignal-protocol --precise <version>` only when the selected revision requires it, then review `Cargo.lock` as a complete dependency change.
5. Run formatting, tests, strict Clippy, release builds, protocol round-trip tests, replay/out-of-order tests, migration tests, and carrier tests.
6. Run the upstream libsignal test suite at the selected revision when practical.
7. Review the adapter API diff. Application-facing SafeChat types must remain stable; upstream types must not leak through the transport modules.
8. Record the revision, test results, and compatibility decision in the change log before merging.

## Compatibility policy

The adapter exposes SafeChat-owned request, session, and ciphertext types. It owns serialization at the carrier boundary and persistence transactions around libsignal state changes. A libsignal update is not complete until old SafeChat state either migrates explicitly or is rejected with a documented recovery path.

The current branch has linked and compiled the pinned upstream implementation. The
Signal adapter initializes identities, prekeys, sessions, and encryption/decryption
through libsignal, with SQLCipher-encrypted SQLite persistence around the official
reference stores. The profile password is required to unlock the database.
Bundle export, UI startup, sending, and receiving maintain a 32-entry
one-time-prekey target below an 8-entry low-watermark and rotate signed
prekeys after 30 days. Rotation retains old records for compatibility;
bounded retirement and operational monitoring remain production work.
The former custom handshake, session, ratchet, and envelope commands have been
removed from the production binary.

## Production TODO: key lifecycle and recovery

The MVP currently has the cryptographic building blocks but not the complete
operational key lifecycle. Before production deployment, implement and test:

- monitoring and explicit diagnostics when the one-time-prekey inventory is
  low, signed-prekeys are stale, or rotation cannot be completed;
- bounded retirement/overlap policy for rotated signed-prekeys and delayed
  messages;
- monitoring and explicit diagnostics when prekeys are depleted or stale;
- identity-key replacement, device revocation, and session invalidation after
  suspected compromise;
- an out-of-band recovery flow that publishes the new fingerprint and requires
  peer re-verification;
- crash-injection validation of transactional persistence for prekey
  consumption, ratchet updates, and rotation.
- a documented migration path for existing plaintext identity databases.

Until these are complete, existing sessions remain usable, but new
asynchronous sessions and compromise recovery require manual operational
procedures. This is acceptable for controlled MVP testing, not for unattended
production use.

## Licensing

The upstream dependency currently identifies itself as AGPL-3.0-only. Before distributing SafeChat, obtain a legal review of the resulting combined distribution and confirm that the chosen libsignal package and bindings are appropriate for the project.
