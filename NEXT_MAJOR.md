# Next major release

Breaking changes deferred to the next major version. The SDKs version in lockstep on major.minor, so these ship in the same release as the other SDKs' deferred changes. When one lands, move it to `CHANGELOG.md` and delete it here.

## `login()` fires `onFailure` once on a network failure

- **Now (1.4.x):** when `/auth/validate` is still unreachable after the network retry, `login()` calls `onFailure("network_error", error)` from `_postJson` and then `onFailure("login_failed", error)`, and resolves `false`. Without an `onFailure` callback the first call exits the process, so the exit happens on `network_error`. Check-in network failures already fire once (1.4.0).
- **Planned:** fire once, as `onFailure("login_failed", error)` where `error.code` is `network_error` or `timeout`, matching check-ins and the C++ SDK. Same change as the C# SDK's `Login()`.
- **Why deferred:** callers that react to the `network_error` reason would stop seeing it, and callers counting callbacks would see one instead of two.
- **Touches:** the `_postJson("/auth/validate", body)` call in `_validateAndStore` (`authforge.mjs`; pass `{ skipFailureHook: true }`), a login network-failure test, the "`network_error` (login only)" reason in `README.md` / `AGENTS.md`, AuthForgeDocs `sdk/node.mdx`.
