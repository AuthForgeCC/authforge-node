# Changelog

## 1.4.0

### Behavior changes for callers

- **Typed heartbeat errors.** `onFailure("heartbeat_failed", error)` now always receives an `AuthForgeError` (new export) with `code`, `transient` and `fatal`. For server errors `error.message` equals the code.
- **Classification.** Only a definitive allowlist is fatal: `revoked`, `expired`, `hwid_mismatch`, `blocked`, `session_expired`, `malformed_request`, `app_disabled`, `invalid_app`, `signature_mismatch`. Everything else is transient, including `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `bad_request`, `invalid_key`, every `http_error_<status>` and unknown codes.
- **Transient failures keep checking in.** Previously any heartbeat failure stopped the timer. Now the session is kept and the next interval checks in again; once the signed session's TTL has passed, a transient failure is reported as `session_expired`.
- **Definitive failures clear the session first.** The stored session is cleared (as `logout()` does) and check-ins stop before `onFailure` runs, so `isAuthenticated()` is already `false` there. `onFailure` may call `logout()`, `isAuthenticated()` or `login()`, and a check-in still in flight when `logout()`/`login()` runs is discarded.
- **`unexpected_response`.** A failed check-in only counts as a verdict when its body is `{"status":"failed","error":"<code>"}`. Any other failure body (for example from a proxy) is reported as transient `unexpected_response`, with the raw `status`/`error` in the message.
- **Rate-limit retries.** Only `rate_limited`, or HTTP 429 with no error code, is retried (after 2s, then 5s). `no_credits`, `demo_quota_exceeded` and `app_burn_cap_reached` (also HTTP 429) are no longer retried immediately. This also applies to `login()` and `validateLicense()`.
- **One callback per heartbeat network failure.** Heartbeat network failures are reported once, as `heartbeat_failed` with code `network_error` or `timeout`; they no longer also fire `onFailure("network_error")`.
- **Unknown server codes are passed through** instead of being collapsed into `unknown_error`.
- **New exports:** `AuthForgeError`, `isTransientError(errorOrCode)`, `transientErrorCodes`, `definitiveErrorCodes`.
- **`http:` base URLs** are supported for `apiBaseUrl` (for example a local test server).
