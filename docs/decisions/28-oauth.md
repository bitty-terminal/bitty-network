# #28: OAuth Credential Flow Architecture and Security Boundary

Status: decided (co-signed with `bitty-ai` owners for Issue #28, CTX-0066).

Parent: #16 (future backends umbrella).

## Purpose and scope

This decision record establishes the authoritative architecture, security boundary,
and transport integration contract for OAuth credential flows between `bitty-network`
(the L1 network transport extension) and `bitty-ai` (the AI runtime and provider plugin
ecosystem).

The scope encompasses:
- Token storage and references (opaque handles vs host store).
- Token refresh, rotation, and connection pool lifecycle invalidation.
- Scope narrowing, dual-origin binding, and consent separation.
- Strict secret redaction across diagnostic, trace, and debug interfaces.
- Feature gate posture for `oauth = []` in `bitty-network`.

Explicitly out of scope:
- Vendor-specific OAuth client logic (OpenAI, Anthropic, Google, Azure AD, etc.),
  which resides exclusively within Level 2 provider plugins.
- Interactive authentication dialogs and user prompt flows, which are owned by the
  terminal workspace UI.

## Normative sources this specification must not weaken

1. **Secret Invariant** (`bitty-ai-docs/providers/provider-plugin-boundary.md`):
   "A model can use credentials; a model must never see credentials."
2. **Hardest Boundary** (`BN-7`, `bitty-docs/bitty-terminal/specifications/bitty-network-candidate.md`):
   `core ≠ network ≠ AI`. The AI runtime holds no network stack of its own; it
   consumes `bitty-network` via typed API calls behind capability checks.
3. **Consumer Order** (`BN-8`):
   AI providers are the primary consumer exercising `client` plus `http` transport,
   with configuration and credential handling owned by the AI corpus.
4. **Redaction Controls** (`P0-AC-026`, `PP-2`, `PP-4`, `AIQ-5A`):
   Pre-queue and pre-write typed redaction; zero secret leakage in logs, traces,
   diagnostics, or debug representations.
5. **Proxy Authentication and Connection Pool Partitioning** (`docs/decisions/25-proxy-auth.md`):
   Dual-origin validation via `CanonicalOrigin`, connection pool keys via `PoolKey`,
   and active lease tracking and invalidation via `ScopeRegistry` and `AuthorizationLease`.
6. **Workspace Standards**:
   `#![forbid(unsafe_code)]`, zero `unwrap`/`expect`/`panic` in library code, and
   100% English documentation and code syntax.

## Architectural split: bitty-ai vs bitty-network

The division of responsibility adheres strictly to the small-core and separation-of-concerns
principles:

| Responsibility | Owning Component | Description |
| :--- | :--- | :--- |
| **Model Abstraction & Policy** | `bitty-ai` Core (`crates/bitty-ai-runtime`) | Pure `std`-only contract (`ModelProvider`), routing, selection, budget accounting, and provider-independent errors. Holds zero network code, zero async runtimes, and zero raw secrets. |
| **OAuth Flow & Token Management** | `bitty-ai` Provider Plugins (Level 2) | Executes vendor-specific OAuth 2.0 PKCE, authorization code exchanges, device code flows, token refreshes, and reads/writes opaque credential handles (`secret://...`) in the host secret store. |
| **Secret Container** | `bitty-ai` Runtime (`crates/bitty-ai-runtime/src/secret.rs`) | `SecretField` wraps raw token bytes; unconditionally redacts in `Debug` and `Display` (`[redacted secret]`). Exposes bytes only via the dedicated `expose_for_adapter()` seam. |
| **Network Transport & Pooling** | `bitty-network` (`crates/bitty-network`) | L1 Core Network Extension. Executes capability-checked HTTP and WebSocket transport. Manages connection pooling, proxy authentication (`ProxyCredentialProvider`), and pool invalidation (`ScopeRegistry`). |

`bitty-network` is not a vendor OAuth client, is not a token vault, and performs no
ambient keyring discovery. It accepts pre-authorized requests or proxy credential
providers and enforces transport safety, capability gates, and connection draining.

## The Four Pillars of OAuth Credential Handling

### 1. Opaque Token Storage

- **Reference-not-value rule**: Configuration files and runtime models must never contain
  literal token strings. All configuration references credentials via opaque URIs:
  `credential = "secret://<provider>/<identity>"`. Literal credentials in configuration
  fail schema validation.
- **Host Secret Store**: Real OAuth access tokens, refresh tokens, and client secrets
  reside in the secure host secret store (OS keychain or encrypted user store) outside
  process memory.
- **Handle isolation**: The UI and configuration layers observe only `configured = true`.
  Prompts, context compilers, Lua scripts, and journal logs never observe token values.

### 2. Token Refresh and Connection Lifecycle

- **Proactive Refresh**: Provider adapters manage token refresh in the background prior
  to access token expiration.
- **Connection Pool Invalidation**:
  When an OAuth token expires, is refreshed, or is revoked:
  - The adapter triggers invalidation in `bitty-network`'s `ScopeRegistry`
    (`crates/bitty-network/src/proxy.rs::pub struct ScopeRegistry`) via generation or
    scope epoch progression.
  - Active connection pools keyed by `PoolKey` (`crates/bitty-network/src/proxy.rs::pub struct PoolKey`)
    are marked inactive, and in-flight `AuthorizationLease`
    (`crates/bitty-network/src/proxy.rs::pub struct AuthorizationLease`) instances are drained.
  - Sockets with obsolete authorization credentials are closed and never reused for subsequent
    requests.
- **Fail-Closed Semantics**: If a token refresh fails or credentials are revoked,
  outgoing requests fail closed immediately with a typed error. The transport never falls
  back to unauthenticated egress.

### 3. Scope Narrowing and Origin Binding

- **Least Privilege**: OAuth tokens must be requested with the narrowest functional scope
  necessary for the configured provider operations.
- **Dual-Origin Binding**: Tokens are bound to exact destination endpoints verified via
  `CanonicalOrigin` (`crates/bitty-network-core/src/origin.rs::pub struct CanonicalOrigin`).
  A bearer token issued for `https://api.openai.com:443` cannot be transmitted to any
  other origin or unverified proxy.
- **Consent Separation**: Outgoing requests carrying provider credentials require distinct
  `ai.provider` consent in addition to standard `NetworkCapability` allowlist verification.
- **Redirect Stripping**: HTTP 3xx redirects to a distinct origin unconditionally strip the
  `Authorization` header before re-evaluating capability allowlists and proxy bypass rules.

### 4. Typed Secret Redaction

- **Pre-Queue / Pre-Write Redaction**: Strict compliance with `PP-2`, `P0-AC-026`, and `AIQ-5A`.
- **Typed Container**: Tokens are held in `SecretField` (`crates/bitty-ai-runtime/src/secret.rs`),
  whose `Debug` and `Display` implementations emit `[redacted secret]` unconditionally.
- **Transport Redaction**:
  - `Request` (`crates/bitty-network-api/src/lib.rs::pub struct Request`) and `Response`
    formatters redact all header values (`[redacted]`), preserving header count and names
    without leaking bearer tokens.
  - `NetworkError` (`crates/bitty-network-api/src/lib.rs::pub enum NetworkError`) formats
    stably without echoing URLs, query parameters, denied domains, or tokens.
  - No secret canary ever appears in child process outputs, logs, or error strings.

## Gate posture: `oauth = []`

- The `oauth = []` feature gate is retained in `crates/bitty-network/Cargo.toml`.
- Compiling with `--features oauth` introduces no ambient token scraping, no automatic
  keyring inspection, and no network I/O outside explicit caller requests.
- When offline or without capabilities, `OfflineNetworkService`
  (`crates/bitty-network/src/offline.rs::pub struct OfflineNetworkService`) continues to fail
  closed with `NetworkError::Offline`.
- The CI feature matrix verifies the `--features oauth` leg on every build.

## Security review sign-off

The revisit criteria defined in the initial deferral note are fully satisfied:
1. **Approved Design**: The architecture co-signed above establishes the split between
   `bitty-ai` provider plugins (token lifecycle and storage) and `bitty-network`
   (transport carrier, pool invalidation, and redaction).
2. **Security-Corpus Review**: Reviewed against `PP-2`, `P0-AC-026`, `AIQ-5A`, `BN-7`,
   and `BN-8`. Verified that credentials remain completely absent from `bitty-ai` Core
   and `bitty-network` transport memory outside explicit adapter egress.
3. **Sign-off Recorded**: Co-signed and accepted under joint authority of `bitty-network`
   and `bitty-ai` maintainers (Issue #28, Task CTX-0066).

## Verification plan and property pins

- `crates/bitty-network/tests/oauth.rs`:
  - `oauth_gate_compiles_and_preserves_fail_closed_offline_behaviour`:
    Validates that the offline backend fails closed with `NetworkError::Offline` when
    compiled with or without the `oauth` feature.
  - `oauth_bearer_token_is_strictly_redacted_in_request_debug`:
    Proves that bearer tokens injected into `Authorization` headers are completely
    redacted in `Debug` representations and leak zero canary bytes.
  - `network_error_never_leaks_token_or_credential_canaries`:
    Proves that `NetworkError` representations leak no secret canary data.
- `crates/bitty-network/tests/offline.rs`:
  - Validates `#[cfg(feature = "oauth")]` fail-closed behaviour in the CI matrix.

## Acceptance criteria

- `docs/decisions/28-oauth.md` updated to decided and co-signed status.
- `crates/bitty-network/Cargo.toml` and documentation synchronized.
- All quality gates pass:
  - `just check`
  - `just check-http`
  - `just check-websocket`
  - `cargo deny check`
  - `cargo test -p bitty-network --test oauth`
  - `cargo test -p bitty-network --test decision_citations`
- Zero compiler warnings, zero linter warnings, zero unsafe code.

## References

- `docs/decisions/25-proxy-auth.md` - Authenticated proxy credential handling
- `crates/bitty-network/Cargo.toml` - Feature definitions and dependency pins
- `bitty-ai-docs/providers/provider-plugin-boundary.md` - AI provider boundary & secret invariant
- `crates/bitty-ai-runtime/src/secret.rs` - Typed `SecretField` container
