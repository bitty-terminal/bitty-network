# bitty-network Documentation

## Architecture

- [Crate Structure](architecture/crate-structure.md) - Overview of the modular crate architecture

## Lua Integration

- [Lua Integration Design](lua-integration/design.md) - Complete design for exposing network capabilities to Lua plugins
- [Dependency Sharing Strategy](lua-integration/dependency-sharing.md) - Shared network runtime across Lua plugins

## Architectural Decisions

- [21: TLS Policy](decisions/21-tls-policy.md) - Unified TLS provider, CA bundles, and mTLS policy
- [24: PAC Evaluation](decisions/24-pac.md) - PAC evaluation and documented proxy precedence
- [25: Authenticated Proxy](decisions/25-proxy-auth.md) - Authenticated-proxy credential handling and transition criteria
- [26: Server Feature](decisions/26-server.md) - Direction decision for server/listen capabilities
- [27: QUIC Transport](decisions/27-quic.md) - Direction decision for QUIC transport
- [28: OAuth Credential Flow](decisions/28-oauth.md) - OAuth credential flow and provider integration
- [29: Proxy Feature Gate](decisions/29-proxy.md) - Feature gate semantics for proxy routing
- [30: Service Bridge](decisions/30-bridge.md) - Service bridge and external network daemon direction
- [31: Inspector Feed](decisions/31-inspector-feed.md) - Network inspector feed audit vocabulary and sink trait

## Implementation Plans

- [25: Proxy Auth Transition Plan](plans/25-proxy-auth-transition-plan.md) - Concrete transition plan for the 14 criteria of #25

## API Documentation

Run `cargo doc --workspace --no-deps --open` to view the full API documentation.

## Quick Links

- Main crate: `bitty-network`
- API types: `bitty-network-api`
- Core utilities: `bitty-network-core`
- DNS resolution: `bitty-network-dns`
- TLS provider: `bitty-network-tls`
