# #31: inspector feed — per-plugin per-host audit entries and a fail-closed sink

Status: decided at design stage; nothing here is implemented. The vocabulary,
the sink seam, the fail-closed rule, and the bounds are specified and no code
supplies them. The issue stays open, implementation and third-party use remain
gated (CTX-0023).

Parent: #16 (future backends umbrella). RFC: OQ-085.

## How to read this record

### Specified is not implemented

Every requirement below is **[specified, not implemented]**. No type, trait,
constant, module, or bound in this record exists in `bitty-network-api` or
`bitty-network` at the time of writing, and this record does not claim that any
does. The [Transition criteria](#transition-criteria) list what must exist
before an implementation may start, not what exists now.

### Current-state claims

Five statements below rest on the current shape of this repository rather than
on anything this record decides, and each names the property it rests on so a
reader can check it:

- `bitty-network-api` is the single network vocabulary, is dependency-free
  (`std` only), performs no I/O, spawns no background task, and owns the
  stable consumer-facing types (`NetworkCapability`, `Request`, `Response`,
  `WebSocketRequest`, `NetworkError`, `NetworkService`).
- `bitty-network` owns the implementations behind `NetworkService` and already
  carries a redaction vocabulary in `crates/bitty-network/src/diagnostics.rs`:
  `redacted_url`, `redacted_headers`, `summarize_body`, `connect_authority`,
  and the placeholders `REDACTED`, `INVALID_HOST`, `REDACTED_URL_VALUE`.
- The capability check is the only admission gate, it runs before dispatch on
  every service call, and it produces exactly two admission errors:
  `NetworkError::Offline` for a deny-all capability and
  `NetworkError::Denied` for a host, port, or method the grant does not cover.
  It does **not** distinguish the layers inside `NetworkError`: a host miss, a
  port miss, a method miss, and a request with no determinable port all return
  the same `Denied { domain }`, and the only thing that separates them is which
  layer of the check refused.
- Every followed redirect hop is canonicalized and re-checked with
  `check_request` before anything is sent to it, so a hop is a separate check
  and a separate outcome rather than part of the hop that redirected to it.
- No audit or inspector vocabulary exists anywhere in this repository: no
  entry type, no sink trait, no emitter, no feed, and no bound.

A current-state claim with no property behind it is unverified. Because no
criterion in this record is met by the current tree, and because the criteria
are written as requirements rather than as descriptions, the five claims above
are re-read at implementation review rather than pinned.

## Decision

The network crate owns the **vocabulary** of an inspection feed: one entry type
keyed per plugin per host, a closed outcome vocabulary that keeps "nothing
happened" separate from "the effect may have happened", a sink trait, the
redaction rules that keep the feed from becoming an exfiltration channel, and
the retention bounds. The **host** owns the sink: where entries go, how long
they live, and what the Network Inspector shows. The split is the same one the
rest of this repository already draws — `-api` names network work and performs
none of it — and it is what keeps the consumer rule intact: plugins depend on
`bitty-network-api` only, and a plugin must not be able to choose, reach, or
forge the record of its own egress.

The feed is emitted once per capability check, synchronously, at the point
where the check's outcome is known. There is no queue inside this crate, so
there is no bound on a queue and no drop policy for this crate to own. The
fail-closed rule is the load-bearing part: a check whose entry cannot be
recorded does not proceed, and the condition is reported to the host as a
latched, queryable health value rather than as a dropped entry.

## Audit entry vocabulary

### The per-plugin per-host key

The issue asks for per-plugin per-host keying. The key is a triple:

- **`principal_id`** — an opaque handle minted by the host for one plugin
  instance, not a plugin name, not a manifest path, and not anything the plugin
  supplies about itself. It is bounded (see [Cardinality and
  redaction](#cardinality-and-redaction)) and drawn from a closed alphabet.
- **`host`** — the destination host exactly as the capability check normalized
  it, so the feed's host and the host the gate judged are the same string.
- **`port`** — the resolved effective port: the explicit port when the request
  carries one, otherwise the scheme default. It is never absent.

What makes the triple unique is that no two of its components can stand in for
each other, and that a plugin cannot choose any of them:

- A plugin **name** is not a principal. Two instances of one manifest, or one
  plugin granted two different capabilities, share a name; keying on it merges
  them, and a denial recorded for one becomes readable as a denial for the
  other. The host-issued handle keeps them apart, and because the plugin never
  mints it, it cannot be forged or widened from the plugin side.
- The **port** is the third axis the gate already enforces, through
  per-domain port grants and the port check on a request. Without it,
  `example.com:443` and `example.com:8443` collapse into one bucket and a
  port-restricted grant is invisible to an inspector.
- The **host** is included so a key never spans origins, which is what makes
  the per-key retention bound meaningful and what lets an Inspector group by
  origin.

The key identifies a **time series**, not an entry. Two entries can share a
key, so the key alone is not an entry identity. Entry identity is the key plus
**`seq`**, a counter that is monotonic across the whole feed, starts at zero,
and is incremented once per recorded entry. `seq` is unique per entry within
one process, so it identifies an entry on its own and orders the entries under
a key. It restarts when the process restarts, so it is not a durable identifier
and a consumer must not treat it as one; the sink's own retention and the feed
health below are what bound and expose history. A feed-wide counter rather than
a per-key one is what keeps the emitter's own state O(1) — a per-key counter
map would grow with the number of distinct hosts a long-lived process ever
sees, which is unbounded.

The key is exposed as its own type with a `key()` accessor on the entry, so the
sink indexes by a value rather than re-deriving a triple from three fields and
getting the composition wrong.

### Entry fields

The entry is a fixed set of scalars and closed enums. There is no free-text
field, and that is a deliberate constraint rather than an omission: a
free-text field is the one thing that would let a plugin write arbitrary bytes
into a host-side durable store.

| Field            | Type                 | Meaning                        |
| ---------------- | -------------------- | ------------------------------ |
| `principal_id`   | bounded `String`     | host-issued plugin handle      |
| `host`           | bounded `String`     | normalized host, safe alphabet |
| `port`           | `u16`                | effective port, never absent   |
| `kind`           | `ExchangeKind`       | `Http` or `WebSocketHandshake` |
| `method`         | `Option<HttpMethod>` | `Some` iff `kind` is `Http`    |
| `observed_at_ms` | `u64`                | host-supplied ms timestamp     |
| `seq`            | `u64`                | feed-wide counter from zero    |
| `decision`       | `AuditDecision`      | `Allowed` or `Denied`          |
| `outcome`        | `AuditOutcome`       | what happened to the attempt   |

`kind` and `method` are separate because a WebSocket handshake has no verb.
The `Option` is closed rather than open: it is `Some` exactly when `kind` is
`Http` and `None` exactly when `kind` is `WebSocketHandshake`, which is a
decidable invariant a test can pin and a consumer can exhaustively match. The
method reuses the existing `HttpMethod` enum rather than introducing a second
verb vocabulary.

`observed_at_ms` is supplied by the caller. The network crate never reads a
clock: `-api` performs no I/O, and a caller-supplied timestamp keeps the feed a
pure function of the call sequence, so it is deterministic under test without
threads, sleeps, or a fake-clock dependency. The value is recorded as supplied
and is neither validated nor derived; the host owns its clock and its epoch.

### The outcome vocabulary

`decision` is the gate's verdict and answers the issue's allow/deny question.
`outcome` is what happened to the attempt. They are separate fields because
they answer different questions and collapse differently.

`AuditDecision`:

- `Allowed` — the capability check passed.
- `Denied` — the capability check refused; the transport was not entered.

`AuditOutcome`:

- `Refused { cause }` — refused before any transport was entered. Nothing
  happened, and nothing needs reconciling. `cause` is a closed `RefusedCause`:
  `Offline` (deny-all capability), `Host` (host not granted), `Port` (port not
  granted), `Method` (method not granted), or `Malformed` (the request named no
  determinable port). It is a closed enum, not text, because the check already
  knows which layer refused. How the emitter learns that is an implementation
  gap, named after the invariant below.
- `Completed` — the transport was entered and the exchange finished. The
  response reaches the caller through the existing service return path; the
  feed does not copy it.
- `Undelivered { cause }` — the transport was entered and the attempt failed in
  a way that proves nothing reached the peer: connection refused, name
  resolution failure, or a handshake failure before request bytes were written.
  `cause` is a closed `UndeliveredCause` over exactly those cases. Nothing
  happened.
- `EffectUnknown { cause }` — the transport was entered and the effect is
  uncertain: the exchange may have been received and acted on, and the
  acknowledgement was lost. `cause` is a closed `EffectUnknownCause`:
  `DeadlineExpired`, `AcknowledgementLost`, `PeerClosedDuringExchange`, or
  `AbandonedAfterDispatch`. The caller must reconcile — status inspection or
  user direction — before retrying, and must never retry blindly, because a
  retried non-idempotent exchange duplicates an effect that may already have
  happened.

One invariant ties the two fields together and is the reason they are separate:

> `decision` is `Denied` if and only if `outcome` is `Refused`.

A denied attempt never reaches a transport, so a `Denied` entry can never carry
`Completed`, `Undelivered`, or `EffectUnknown`; and an entered attempt was
allowed, so those three can never accompany `Denied`. The invariant is
decidable, and a constructor that cannot represent a violation makes it
structural rather than a convention.

**One gap the implementation has to close, named here so it is not discovered
during it.** The refusal cause is the layer that refused, and the capability
checker's error type does not carry that layer: a host miss, a port miss, a
method miss, and a request with no determinable port all surface as the same
`NetworkError::Denied { domain }`. An emitter that only reads the error cannot
fill in `cause` and must not guess it from the request.

Two ways to close it, and this record does not choose between them because the
choice is a change to the capability layer's surface rather than to the feed:

- the emitter evaluates the same layered checks itself and records the layer it
  refused at, which keeps the error type untouched and duplicates the check
  order; or
- the capability layer exposes the refusal layer as a typed value alongside the
  error, which widens the `-api` vocabulary additively.

The second is the better long-term shape and the first is the smaller change.
Either is acceptable to this record; what is not acceptable is an implementation
that derives the cause from the request, or that collapses the four layers into
one recorded cause and calls the field a closed enum anyway.

### Keeping "nothing happened" separate from "maybe happened"

The property a consumer needs, and the reason this record exists, is that a
caller can always tell whether an exchange may have taken effect. `Refused` and
`Undelivered` mean nothing happened. `Completed` means it happened and the
result is known. `EffectUnknown` means it may have happened and must be
reconciled. Collapsing any two of those is what makes a feed useless for the
case it exists to serve, so the entry exposes the distinction as data rather
than leaving it to be inferred from text:

- `AuditOutcome::may_have_had_effect()` is `true` for `EffectUnknown` and
  `false` for every other variant. It is the reconciliation predicate, and it
  is a method on the type so no consumer re-derives it from a variant name.
- `Refused` and `Undelivered` are two variants, not one "failed" variant, even
  though both mean nothing happened, because they are different facts for an
  inspector: one never left the process, the other left the process and was
  rejected before the peer saw it.
- The "nothing happened" shapes never share a variant with the uncertain one,
  so a consumer that matches on `may_have_had_effect()` cannot accidentally
  treat a denial as a retryable or reconcilable exchange.

The same two names are used for the same two situations in the agent runtime's
tool-execution vocabulary, where a host refusal means no dispatch occurred and
an unknown effect must be reconciled rather than retried. Reusing the names
means a consumer that reads both vocabularies reads one concept under one name
and does not have to learn a translation. The alignment is a naming agreement
only: it grants nothing to either side and authorizes no work on either.

## Sink ownership and the seam

`bitty-network-api` owns the vocabulary and nothing else: the entry type, the
key type, the closed enums, the `may_have_had_effect` predicate, the bounds
constants, the sink trait, and the feed-health type. It adds no sink
implementation, no buffer, no file, no serialization, no thread, and no
dependency.

The host owns the sink: the concrete type, its storage, its eviction policy
within the bounds below, and the Inspector surface that reads it. This split is
the repository's existing consumer rule applied to a new seam. The network
crate cannot be trusted to own the record of its own egress, because the
plugin being audited is the party that would benefit from choosing where that
record lives; and a consumer that depends on `-api` only must be able to name
the entry type and the seam without pulling in an implementation, a logging
dependency, or a transport.

The seam is one trait with one method:

- `AuditSink::record(&self, entry: &AuditEntry) -> Result<(), AuditSinkError>`

`&self`, not `&mut self`, because every `NetworkService` method takes `&self`
and a feed reachable only through `&mut` could not be installed on a service
value. An implementor supplies its own interior mutability, which is the same
arrangement the authorization seam uses in the agent runtime: the trait stays
read-only and the implementor owns the mutability.

The return type is a `Result` because a sink must be able to report that it
could not record, and that report must not be a free-text string: a sink is
host-supplied and therefore outside this crate's redaction guarantees, so text
it produces is not text the feed may carry. `AuditSinkError` is a closed enum
with no payload: `Full` (the sink is at its retention bound), `Unavailable`
(the sink's destination is gone), `Rejected` (the sink refuses this entry under
its own policy). The feed maps any of them onto its own closed health value and
keeps the sink's own text nowhere, because there is no text to keep.

## Where the feed is emitted, and whether it is buffered

**One entry per capability check, emitted synchronously on the calling thread
at the moment the check's outcome is known.** One entry per `NetworkService`
call, no more and no fewer, whether the call succeeds, is denied, or fails.

The emit point is the capability-check boundary inside each backend: after the
check, before dispatch, and — for an attempt that entered the transport — at the
point its terminal outcome is known.

- The offline backend checks and never enters a transport, so only `Refused` is
  reachable there. Emitting its denials is not redundant with returning them:
  the returned error reaches one caller, the entry reaches the Inspector, and
  the deny-all case returns the same error for every host, so without an entry
  a sweep of denied hosts is invisible.
- The HTTP backend emits `Refused` at the refusal, and `Completed`,
  `Undelivered`, or `EffectUnknown` at the terminal outcome of an entered
  exchange.
- The WebSocket backend does the same over `check_handshake`, before dialing.

**It is not buffered.** There is no queue in `bitty-network-api` and none in
`bitty-network`, so the record states no queue bound: there is no queue. A
bounded internal queue would require this crate to choose a drop policy, and
which entries a host's Inspector misses is the host's decision, not the audited
party's crate. Synchronous emission also keeps `seq` order equal to dispatch
order, which is what makes the feed replayable, and it keeps the whole feed
deterministic for a fixed call sequence under a caller-supplied clock and sink.

The cost is stated rather than hidden: the sink runs on the request path, so a
slow sink adds latency to every check. That is the host's choice, and the host
accepts it explicitly by installing a non-blocking sink or a sink whose
worst-case cost it owns.

Redirects are covered by the same rule rather than by a special case. Each hop
re-checks against the handed grant, so a cross-host redirect produces two
entries under two different keys, with consecutive sequence numbers — which is
exactly what an inspector needs, because a redirect is the case where egress
moved without a new caller request.

**What is bounded, then.** Two bounds apply, and neither is a queue. This
crate's own state is O(1) per feed: one sequence counter and the latched health
value, and nothing else — no key table, no history, nothing retained here at
all. The host's retained history is bounded by the constants below. The gap the
feed cannot record is bounded by the fail-closed rule: while the feed is
latched, no exchange proceeds, so the unattributable window does not grow.

## Fail-closed behaviour when the sink is absent or errors

Silently dropping an audit entry is itself a security failure, because an
egress that leaves no attributable record is an egress the capability model can
no longer account for. The feed therefore never drops an entry quietly. It has
exactly three states, and the two that are not `Accepting` are separate variants
that cannot be confused with each other or with success.

`AuditFeedHealth` is one type with three variants:

- `Accepting` — a sink is installed and the last record succeeded.
- `NoSink` — no sink was ever installed. This is a **construction-time
  posture**, not a runtime fault. It is stable, it names a deliberate
  configuration, and it is not a per-entry event: there is no entry to lose,
  because no destination was ever promised.
- `SinkFailed { cause, first_dropped_seq, last_dropped_seq }` — a sink was
  installed and a record did not succeed. This is a **latched runtime fault**.
  It latches on the first failure and does not clear on its own. The two
  sequence numbers bound the gap: an Inspector renders "audit gap" over exactly
  that interval instead of showing a quiet period that never happened.

The distinction is therefore explicit and load-bearing: absence is a
construction fact about the feed, erroring is a latched runtime fact about a
destination, they are different variants of one health type, and neither is ever
reported as success. A host that installed no sink and a host whose sink broke
cannot be confused, and neither can be confused with a feed that is working.

**The fail-closed rule.** A check whose entry cannot be recorded does not
proceed:

1. The first record that fails latches `SinkFailed` and remembers the sequence
   number the entry would have carried.
2. While latched, every capability check is **refused before dispatch**, with
   the same `NetworkError::Offline` described below. No socket is opened, no
   name is resolved, no bytes are written, and the exchange does not happen. The
   feed keeps _attempting_ to record while latched, because an `EffectUnknown`
   raised during the fault is exactly the entry that must not be lost; a record
   that fails again extends `last_dropped_seq`.
3. Clearing the fault — a repaired sink, or removal of the sink, which moves
   the feed to the stable `NoSink` posture — restores accepting behaviour
   without a process restart.

**No entry is fabricated for a check the feed could not record.** A synthesised
entry would be precisely the false assurance this rule exists to prevent, and it
would put a `Refused` outcome into the feed for a denial that the capability
gate never issued. The gap is reported through the health value instead, which
is why the health value is part of the contract and not a diagnostic extra.

**Whether the failure reaches the request's caller, and how.** Not through the
existing `NetworkService` return type, and this is the decision most likely to
be argued with, so the reasoning is explicit.

The exchange that would go unrecorded is refused with the existing
`NetworkError::Offline`, and the reason is not smuggled into a new error
variant. In this crate `Offline` already means "this backend performed no
work": the offline backend returns it both for a deny-all capability and for an
allowlist hit, because it owns no sockets. Using it for "no work happened
because the check could not be recorded" is the same claim, stated by a
different cause, and it is exact.

Three things follow, and each is a deliberate trade:

- **The network error taxonomy does not widen.** The existing variants —
  `Denied`, `Offline`, `Timeout`, `Budget`, `CountBudget` — are statements
  about the network. A record-keeping failure is not a network fact, and adding
  a variant for it would make a monitoring component's health a network failure
  reason, which is the conflation that makes "let a broken sink take down all
  networking" look reasonable. A dedicated variant remains possible and would
  need its own decision, because every consumer matches on this taxonomy; this
  record does not freeze it and does not grant it.
- **The distinction stays visible to the party that can act on it.** The
  caller of a request is a plugin, and a plugin holds no sink and can fix no
  sink; telling it which of two conditions stopped its request would be
  information it cannot use. The host both installs the sink and reads
  `health()`, so the host is the party that receives both the `NoSink` posture
  and the `SinkFailed` latch, and the `NoSink` case is visible at construction
  rather than only after a loss.
- **The blast radius is bounded and loud.** Only the affected exchange and
  every check after it are refused, not the process; the fault is a latched,
  named condition with a bounded gap; and the recovery condition is explicit.
  The alternative — keep serving and count the loss — is rejected because an
  Inspector cannot distinguish a quiet period from a broken feed, which is the
  silent drop this rule exists to prevent.

## Cardinality and redaction

The feed must not become an exfiltration channel: it is host-side, durable, and
reachable from plugin-controlled work, so anything a plugin can shape is a way
to write into a store the plugin does not own.

**No field can carry a credential.** There is no URL field, no header field, no
body field, no path field, and no free-text field. Every field is a bounded
handle, a safe host, a port, a host-supplied timestamp, a counter, or a closed
enum. A credential has nowhere to go, and that is stronger than a rule saying
credentials must be removed.

**The redacted URL is the one this repository already has.** Any URL that
reaches the feed boundary is passed through
`crates/bitty-network/src/diagnostics.rs::redacted_url` first, which yields
`scheme://host:port/path` with userinfo, query, and fragment dropped, an
unparseable input as `[redacted-url]`, and a control-bearing host as
`[invalid-host]`. The feed defines no second redaction form. Concretely,
`https://user:secret@example.com:8443/a?token=x#f` becomes
`https://example.com:8443/a`.

The feed then selects **narrower** fields from that form, and the narrowing is
part of the decision:

- The feed stores `host` and `port` as separate fields and stores **no** path.
  The path survives in the redacted URL because it is useful correlation data in
  an error message, but it is caller-controlled, frequently identifying
  (`/users/<uuid>`), and unbounded in length. An inspector attributes egress by
  origin, not by which object was fetched.
- The feed stores **no** header name and **no** header value. The request's
  headers never reach the feed. Header values are unconditionally redacted
  elsewhere in this crate for the same reason given there — an innocuous-looking
  header can carry a secret — and header names would need bounding for a
  benefit no consumer has asked for. A future need for header names requires a
  new decision, not an extension of this one.

**A rendered entry is composed from `host` and `port`, never from the request
URL.** That is what makes the redaction structural: there is no stored URL to
leak, and the composition rule cannot be bypassed by a caller who supplies a
hostile URL, because the URL is not an input to rendering.

**Bounded strings are rejected, never truncated.** `principal_id` is at most
`MAX_PRINCIPAL_ID_BYTES` (64) bytes and must consist only of ASCII letters,
digits, `.`, `_`, `:`, and `-`. A value that violates either rule is a
construction error, not a shortened value. Truncation would be worse than
rejection here: two distinct principals whose handles share a prefix would
become one key, and a merged key is precisely the attribution defect the key
exists to prevent. `host` is at most `MAX_HOST_BYTES` (253) bytes — the DNS
name limit — and drawn from the safe host alphabet the existing helper already
enforces; a host outside that alphabet is recorded as `[invalid-host]`, which
keeps the entry bounded without recording a value the feed cannot vouch for.

**Cardinality is bounded by construction.** An entry is a fixed set of scalars
and closed enums plus two bounded strings, so its size has a constant ceiling.
This crate retains no history at all, so its cost per feed is O(1) and its cost
per entry is O(1). Everything that could grow without limit is either a bounded
counter or lives in the host's sink under the bounds below.

## Retention bound

The bounds are named constants in `bitty-network-api`, because they are part of
the contract: a host that retains more is non-conforming, and a bound that
lives only in the host's configuration is not a bound.

- **`MAX_ENTRIES_PER_KEY` (`256`)** — entries retained per key, evicted
  oldest-first. Long enough to see a retry loop or a scan walking one host;
  short enough that a flood on a single key cannot dominate the feed.
- **`MAX_ENTRIES_TOTAL` (`8 * 1024`)** — entries retained across all keys,
  evicted oldest-first by `observed_at_ms` and then by `seq`. A global ceiling,
  so a many-key flood cannot grow the feed without limit either.

Eviction is not silent. A conforming sink reports a monotonically increasing
eviction count, and the Inspector shows that history was truncated; a truncated
feed that looks complete is the same defect as a dropped entry that looks
recorded. The feed health value is where the two live side by side, so a
consumer can distinguish "nothing happened to this host" from "we no longer
know what happened to this host".

`seq` is a `u64` and does not wrap in any realistic process lifetime. If it
ever does, the feed's sequence restarts, which a consumer sees as a feed restart
— the same signal as the sink's eviction count, and the reason neither is
load-bearing on its own.

## Security-corpus review note

### Reviewed

- Issue #31, its parent #16, and the decision scope of CTX-0023.
- The current admission path in this repository: the capability check, its two
  admission errors, the offline backend's rejection helpers, and the
  `NetworkService` boundary with its `&self` receivers.
- The existing redaction vocabulary in
  `crates/bitty-network/src/diagnostics.rs`, including `redacted_url`,
  `safe_host`, and the three placeholders, together with its current-state claim
  that wiring those snapshots into the backends' error paths is a follow-up
  merge and not present today.
- The agent runtime's tool-execution vocabulary, for the two-outcome property
  this record's outcome vocabulary is shaped around: a refusal that means no
  dispatch occurred, and an unknown effect that must be reconciled rather than
  retried.
- The merged direction decisions in this directory: client-only by construction
  (#26), QUIC as a direction marker (#27), OAuth deferral (#28), the `proxy`
  gate meaning (#29), the bridge boundary (#30), and the TLS trust and identity
  contracts (#21/#22), whose redaction posture this record follows rather than
  restates.

### Findings

The main design risks were an audit gap that reads as a quiet period, an outcome
vocabulary that merges a denial with an uncertain effect, a feed that becomes a
side channel for plugin-controlled data, and a sink failure that is either
ignored or allowed to stop all networking. The decisions above address each one
explicitly: a latched health value with a bounded, enumerable gap; four outcome
variants with a `may_have_had_effect` predicate and a decidable
`Denied`/`Refused` invariant; no free-text field and rejection instead of
truncation; a feed-wide counter so the emitter's own state stays O(1); and a
fail-closed rule whose blast radius is one exchange plus a repair.

No audit controls were reviewed against an implementation, because no audit
vocabulary, sink, or emitter exists to review. This is a design-stage review of
a specification, not an implementation review and not an approval for
third-party use.

### Gate posture

This record decides the vocabulary and the seam. It authorizes no
implementation, assigns no owner, sets no milestone, and closes no open question
entry in this or any other repository; those are acts of the accepting review
and of the owning team, not of a decision record. Issue #31 stays open: this
record is its prerequisite, not its completion.

The agent runtime's tool-execution vocabulary is a naming reference only.
Aligning the two names creates no obligation on either side and no
authorization to change either vocabulary.

## Transition criteria

Every criterion below is **[specified, not implemented]**, and all of them are
required before an implementation of #31 may start. They are stated as
requirements and are deliberately not weakened to match the current tree, which
supplies none of them.

1. Independent acceptance records this decision and updates the status line.
2. A separately scoped implementation adds the vocabulary to
   `bitty-network-api` — entry, key, the closed enums, the predicate, the
   bounds constants, the sink trait, and the health type — with no dependency,
   no I/O, no background task, no serialization, and no sink implementation, and
   adds one emitter module to `bitty-network` that reaches the feed at every
   check outcome. No manifest or lockfile change is implied by this record.
3. Vocabulary tests pin: `decision` is `Denied` if and only if `outcome` is
   `Refused`; `Refused` and `Undelivered` never report
   `may_have_had_effect`; `EffectUnknown` always does; `method` is `Some` if and
   only if `kind` is `Http`; every enum is exhaustively matchable with no
   wildcard arm.
4. The refusal cause is decided by a real signal, never derived from the
   request: a host miss, a port miss, a method miss, and a portless request
   each record their own `RefusedCause`, and a test proves those four are
   distinguishable from each other and from `Offline`. If the implementation
   takes the additive option above and widens the `-api` capability surface to
   expose the refusal layer, that widening is reviewed as its own vocabulary
   change.
5. Fail-closed tests prove: no sink installed reports `NoSink` and never
   reports `Accepting`; a sink that returns an error latches `SinkFailed`; the
   exchange whose entry could not be recorded does not proceed and yields no
   fabricated entry; every later check is refused before dispatch while latched;
   `first_dropped_seq` and `last_dropped_seq` bracket the gap exactly; and
   clearing the fault restores accepting behaviour with no process restart.
6. Exactly-one-entry tests prove one entry per `NetworkService` call across
   success, denial, and transport failure, that `seq` is monotonic across the
   feed and equals dispatch order, that entries under one key keep their `seq`
   order, and that a cross-host redirect yields two entries under two keys.
7. Redaction tests prove that a canary credential in a userinfo position, a
   query, a fragment, and a header value appears in no entry, in no `Debug` or
   `Display` output, and in no serialized form, and that a rendered line is
   composed from `host` and `port` in the form
   `crates/bitty-network/src/diagnostics.rs::redacted_url` produces.
8. Bound tests prove that an over-long or out-of-alphabet `principal_id` is
   rejected rather than truncated, that two handles sharing a prefix cannot
   collapse into one key, that an out-of-alphabet host becomes `[invalid-host]`,
   and that a conforming sink honours both retention bounds, evicts
   oldest-first, and increments its eviction count.
9. The plugin-identity handoff is specified on the host side: how
   `principal_id` is minted, its stability scope, and what a consumer must do
   across a host restart. This repository does not own that contract and does
   not decide it here.
10. The Network Inspector surface that reads the feed is scoped, specified,
    and reviewed as its own work. This repository ships the feed, not the
    Inspector.
11. Implementation-level security review before any third-party use, covering
    the fail-closed rule under a hostile or full sink, the redaction boundary
    under a hostile host, and the retention bounds under a flood.

A proposal that adds a free-text field, an unbounded retained field, a second
redaction form, a buffered queue with a drop policy inside this crate, or a
silent drop returns for a new decision rather than being folded into this one.
