# Standalone HyperKey browser qualification

This example imports only published Foundation packages. It requires no consumer
SDK, account, database server, transport or application shell. Its explicit
qualification founder authority grants finite native facts after matching its
local fixture evidence. It is not a production identity service.

Install the exact `0.2.0` packages and Playwright, then run:

```sh
npm install
npx playwright install chromium
npm start
# In a separate terminal:
npm test
```

Before publication, Foundation's packed-package qualification harness may install
its three local tarballs instead. No source alias or workspace link is required.
The server resolves package exports and serves the installed generated WASM.

The page creates real native MLS founders with independent X25519 delivery keys.
It stores records in IndexedDB under AES-GCM using nonexportable, purpose-specific
CryptoKeys in a separate key store. Web Locks serialize cooperating writers while
crypto runs; the consumer then publishes all changes in one strict-durability
IndexedDB transaction. All cooperating tabs must use this same adapter and lock.
Reload opens committed state with the stored keys. Forgetting deletes current
Copy custody/native state and retains its terminal readiness record.

The browser test creates two independent founders, verifies conventional
signatures, reloads, confirms the same signature, forgets one Copy, reloads again
and checks that the other Copy stays ready. It also fails on browser exceptions.
IndexedDB reports abort versus completion for this adapter; a page/process crash
recovers through a new coordinator. Host-specific ambiguous commit errors must
be classified through the neutral commit-outcome port when extending this code.

Copy transport, remote approval and production identity are intentionally left to
the consumer. The focused package tests qualify Copy seed delivery using actual
native MLS, plus a separate concrete generic admission integration test. This
example exposes a local `window.qualification` API solely for automated checks.
