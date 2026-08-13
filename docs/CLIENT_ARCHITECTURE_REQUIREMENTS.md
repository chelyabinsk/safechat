# Client Architecture Requirements

This document defines the component boundaries for the desktop UI and future
Android client. The goal is to support Linux and Windows first without making
Android a rewrite, while keeping transports and cryptographic code independently
testable.

## Required dependency direction

```text
Slint UI
    -> UI/application service API
        -> application/chat service
            -> core Signal/session/profile logic
            -> transport interfaces
                -> copy/paste adapter
                -> HTTPS relay adapter
                -> image/media carrier adapters
            -> platform service interfaces
                -> secure storage
                -> files
                -> clipboard
                -> notifications
```

Dependencies point downward only. Core and transport crates must not depend on
Slint, desktop widgets, Android APIs, or platform-specific filesystem paths.
The relay server remains a separate product and must not depend on the client
UI or client application crate.

## Component responsibilities

### UI

The UI owns presentation, navigation, user prompts, validation feedback, and
transport selection. It must not implement Signal encryption, relay framing,
Base64 conventions, message deduplication, or carrier encoding.

The first UI uses Slint. Keep the UI boundary portable so the same application
service can support Linux and Windows first, with a future Android frontend.

### Application service

The application layer coordinates conversations, contacts, message history,
delivery status, retries, and the selected transport. It exposes operations
such as:

```text
list_contacts()
select_transport()
send_message()
receive_messages()
acknowledge_message()
export_bundle()
import_bundle()
export_ciphertext()
import_ciphertext()
```

The API should be asynchronous or callback-based from the UI's perspective.
No UI call may block the Qt event loop on network, database, cryptographic, or
carrier work.

### Core

The core owns Signal identities, sessions, trust, ratchets, encrypted history,
message IDs, recovery, revocation, and carrier-neutral encrypted envelopes.
It must be usable from command-line tests and headless services without a GUI.

### Transports

Every transport moves opaque encrypted bytes and implements the common
transport contract. A transport must not inspect plaintext or own Signal
session state.

Transport-specific details stay inside adapters:

- copy/paste: text encoding and selected paste context;
- relay: HTTPS, authentication, binary message frames, polling, and
  acknowledgements;
- image/media: carrier capacity, embedding, extraction, and transformation
  warnings.

Adding a transport must not require changes to Signal logic or UI message
semantics. The UI may display transport capabilities and errors, but does not
branch on wire-format details.

### Platform services

Platform-dependent behavior must be behind small interfaces:

- secure key/password storage;
- application-data directories and file operations;
- clipboard access;
- file and image pickers;
- desktop/mobile notifications;
- lifecycle and background-work scheduling.

The Linux and Windows implementations may initially share most behavior. An
Android implementation must be able to replace these services without changing
core or transport code.

## FFI boundary

The Qt client should call a narrow C-compatible Rust API or generated binding
layer. Do not expose Rust structs containing transport, SQLite, or libsignal
types directly to QML. FFI values should use stable primitives, owned strings,
byte buffers, explicit error objects, and opaque handles where necessary.

The boundary must define ownership, cancellation, threading, and error rules.
Rust callbacks into Qt must be marshalled onto the Qt thread; cryptographic and
I/O work must run off that thread.

## Cross-platform requirements

The desktop target is Linux and Windows. Android readiness is required even
though Android is a later delivery target:

- no hard-coded path separators or home-directory assumptions;
- no reliance on a long-lived process or unrestricted background thread;
- no synchronous network or database work in UI callbacks;
- credentials and identity databases use platform secure storage policy;
- all user-visible files go through an abstract file service;
- network clients support cancellation, timeout, retry, and lifecycle resume;
- notifications and background polling are capability-dependent;
- desktop-only features degrade explicitly on mobile.

## Transport-selection UX

Transport selection is a user-level choice, not a protocol implementation leak.
The UI should show:

- available transports and their capabilities;
- whether the selected transport is online, manual, or experimental;
- capacity and transformation warnings for media carriers;
- relay TLS and trust status;
- retry or acknowledgement status where supported.

The same conversation and message actions should work regardless of whether
the user selects copy/paste, relay, or a future media carrier. Unsupported
operations must be reported as capabilities, not discovered through protocol
errors after sending.

## Testing requirements

Every component must be testable independently:

- core: session, framing, trust, persistence, and malformed-input tests;
- transports: contract tests using opaque byte fixtures;
- application: fake transport and fake platform-service tests;
- UI service boundary: tests that do not require a display server;
- platform adapters: targeted integration tests on each supported platform;
- end-to-end: at least one Linux relay smoke test and one copy/paste round trip.

Experimental media carriers must be benchmarked separately against clean
carriers and external steganalysis tools. A carrier passing a detector is not a
security guarantee and must not change the core or transport API.

## Acceptance criteria for the first Qt client

The first desktop release is acceptable when it can:

1. create or unlock a profile through the platform service boundary;
2. verify a peer bundle and establish a Signal session;
3. select copy/paste or HTTPS relay without changing conversation code;
4. send, receive, deduplicate, acknowledge, and display message status;
5. remain responsive during crypto, database, and network operations;
6. run the same application-service tests headlessly;
7. build without Android-specific code while preserving the interfaces needed
   for a later Android implementation.
