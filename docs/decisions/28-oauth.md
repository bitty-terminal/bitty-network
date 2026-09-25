# #28: oauth credential flow — deferred

Status: deferred, jointly owned with the bitty-ai corpus (CTX-0015,
lane D).

Parent: #16 (future backends umbrella).

## Decision

No token handling code until the security review passes. Deferred items:

- Token storage and refresh.
- Scope narrowing.
- Secret redaction in logs, errors, and debug output.

The design is worked out with the bitty-ai corpus owners first; the
review is filed with the design, since provider credential handling is a
security-corpus review item. Code follows sign-off, not the other way
around.

## Gate posture

- `oauth = []` remains: no code keys off it; the CI matrix leg plus the
  offline fail-closed test pin the no-op.
- Any credential-shaped API added before the review is a defect, not a
  placeholder.

## Revisit criteria

An oauth slice may start only with: an approved design co-signed by the
bitty-ai owners, a filed security-corpus review, and review sign-off
recorded against this issue.
