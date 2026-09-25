# #31: inspector feed — per-plugin per-host audit entries and a fail-closed sink

Status: decided at design stage; nothing here is implemented. The vocabulary,
the sink seam, the fail-closed rule, and the bounds are specified and no code
supplies them. Four residual risks are accepted rather than closed and are named
where they are decided. The issue stays open, implementation and third-party use
remain gated (CTX-0023).

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

- _Monotone._ `bitty-network-api` is the single network vocabulary, is
  dependency-free (`std` only), performs no I/O, spawns no background task, and
  owns the stable consumer-facing types (`NetworkCapability`, `Request`,
  `Response`, `WebSocketRequest`, `NetworkError`, `NetworkService`).
- _Monotone._ `bitty-network` owns the implementations behind `NetworkService`
  and already carries a redaction vocabulary:
  `crates/bitty-network/src/diagnostics.rs::redacted_url`,
  `crates/bitty-network/src/diagnostics.rs::redacted_headers`,
  `crates/bitty-network/src/diagnostics.rs::summarize_body`,
  `crates/bitty-network/src/diagnostics.rs::connect_authority`,
  `crates/bitty-network/src/diagnostics.rs::safe_host`, and the placeholders
  `REDACTED`, `INVALID_HOST`, `REDACTED_URL_VALUE`.
- _Non-monotone._ The capability check is the only admission gate, it runs
  before dispatch on every service call, and it produces exactly two admission
  errors: `NetworkError::Offline` for a deny-all capability and
  `NetworkError::Denied` for a host, port, or method the grant does not cover.
  It does **not** distinguish the layers inside `NetworkError`: a host miss, a
  port miss, a method miss, and a request with no determinable port all return
  the same `Denied { domain }`, and the only thing that separates them is which
  layer of the check refused.
- _Non-monotone._ Every followed redirect hop is canonicalized and re-checked
  with `check_request` before anything is sent to it, so a hop is a separate
  check and a separate outcome rather than part of the hop that redirected to
  it.
- _Non-monotone._ No audit or inspector vocabulary exists anywhere in this
  repository: no entry type, no sink trait, no emitter, no feed, and no bound.

A current-state claim with no property behind it is unverified. Because no
criterion in this record is met by the current tree, and because the criteria
are written as requirements rather than as descriptions, the five claims above
are re-read at implementation review rather than pinned.

**The three claims marked _non-monotone_ can be made false by an addition, not
only by a removal.** The third, fourth, and fifth claims each describe either
something absent or a rule currently enforced: the absence the fifth names could
be filled by the very implementation this record specifies, a third admission
error could be added, the `Denied` collapse could be split, and a future backend
could stop re-checking each redirect hop. All three are true today. None of them
is pinned by a property test, and a claim that an addition can falsify is
exactly the claim a reviewer cannot re-derive from a later diff, so each is
stated here as true-as-of-writing and re-read at implementation review rather
than treated as a standing invariant. The two _monotone_ claims can only be made
false by removing vocabulary, which a diff shows.

**This file's own citations are review-held, and the repository does not check
them.** The pin that resolves a record's citations to symbols that exist
(`crates/bitty-network/tests/decision_citations.rs::every_citation_in_the_record_names_a_symbol_that_exists`)
is scoped by a constant to a single other document, so nothing in this
repository validates a locator written here. Every `path::symbol` locator in
this file is therefore written in the form that pin classifies — one backticked
span, full repository-relative path, symbol after `::` — so that extending the
pin's scope is a constant change and not a rewrite of this file, and every such
locator was checked by hand against the tree as part of writing this file. That
is a review-held check, not a continuous one: a symbol can be renamed later and
no gate here will notice. Any extension of the pin's scope is its own change
and is not implied by this document.

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

The fields below are the entry's **read** surface. The type exposes no
field-wise constructor, no public field assignment, and no `Default`: it is
built only through the two constructors specified under
[the outcome vocabulary](#the-outcome-vocabulary), which is what makes the
`Denied`/`Refused` invariant structural rather than conventional. Reading a
field is always sound; writing one is not an operation the type offers.

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

`decision` is listed as a field because a consumer reads it, not because a
caller supplies it: no constructor takes a `decision`, so the field is derived
from which constructor was used and cannot be set to contradict `outcome`.

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
  `cause` is a closed `UndeliveredCause` over exactly those cases **and the
  budget and count crossings decided before the attempt reaches the wire** — an
  outbound message rejected on size before the transport is touched, and an
  outbound frame or message count crossing. Nothing happened.
- `EffectUnknown { cause }` — the transport was entered and the effect is
  uncertain: the exchange may have been received and acted on, and the
  acknowledgement was lost. `cause` is a closed `EffectUnknownCause`:
  `DeadlineExpired`, `AcknowledgementLost`, `PeerClosedDuringExchange`,
  `AbandonedAfterDispatch`, **or a budget or count crossing decided after the
  peer has already seen the request** — a response body stopped at the byte
  cap, an inbound message above the per-message cap, an inbound lifetime total
  crossing the aggregate cap, and an inbound frame or message count crossing.
  The caller must reconcile — status inspection or user direction — before
  retrying, and must never retry blindly, because a retried non-idempotent
  exchange duplicates an effect that may already have happened.

**A budget crossing is classified by which side of the wire decided it, and the
two sides land in different variants.** This is stated because the error
taxonomy does not: `NetworkError::Budget` and `NetworkError::CountBudget` are
each produced both by an outbound size check that refuses before a byte moves
and by an inbound cap that trips after the request was sent and the response
arrived. The same variant therefore means "nothing reached the peer" in one
occurrence and "the peer acted and we stopped reading" in another, and an
implementation that maps the variant to a single outcome is wrong for one of
them. The classification this record specifies is the pessimistic one for the
inbound case — an exchange whose response was truncated is not `Completed`,
because the response does not reach the caller, and not `Undelivered`, because
the peer provably received the request; `EffectUnknown` with a budget cause is
the only variant that both withholds a completion claim and forbids a blind
retry. Classifying it as `Undelivered` instead would be the unsafe direction,
since it would tell the caller that nothing happened when the request was
already acted on.

One invariant ties the two fields together and is the reason they are separate:

> `decision` is `Denied` if and only if `outcome` is `Refused`.

A denied attempt never reaches a transport, so a `Denied` entry can never carry
`Completed`, `Undelivered`, or `EffectUnknown`; and an entered attempt was
allowed, so those three can never accompany `Denied`.

**The invariant is structural, and the mechanism is specified here rather than
assumed.** It is decidable, and it is made unrepresentable by construction
rather than by a test, by restricting the type to exactly two constructors and
no others:

- `AuditEntry::refused(key, kind, cause, observed_at_ms, seq)` takes a
  `RefusedCause` and no outcome and no decision. It sets `decision` to `Denied`
  and `outcome` to `Refused { cause }`. There is no argument through which a
  caller could ask for a different outcome.
- `AuditEntry::entered(key, kind, method, outcome, observed_at_ms, seq)` takes
  an outcome drawn from `Completed | Undelivered | EffectUnknown` and no
  decision. It sets `decision` to `Allowed`. There is no argument through which
  a caller could ask for a denial.

With the fields private and no `Default`, no other construction path exists, so
`Refused` is reachable only from `refused` and therefore only alongside
`Denied`, and the other three outcomes are reachable only from `entered` and
therefore only alongside `Allowed`. A violation cannot be written down, so no
test is load-bearing for the invariant; the vocabulary test in the transition
criteria is a regression pin against someone later adding a third constructor or
a public field, not the enforcement.

This is **[specified, not implemented]**. No such type or constructor exists
today, so the invariant is currently neither structural nor enforced; what is
specified is the shape that makes it structural when it is built.

**Two gaps the implementation has to close, named here so they are not
discovered during it.** Neither is closable by reading the error alone.

_The refusal cause._ The refusal cause is the layer that refused, and the
capability checker's error type does not carry that layer: a host miss, a port
miss, a method miss, and a request with no determinable port all surface as the
same `NetworkError::Denied { domain }`. An emitter that only reads the error
cannot fill in `cause` and must not guess it from the request.

_The budget position._ The budget and count variants do not carry which side of
the wire decided the crossing, and the same variant occurs on both sides, so an
emitter that only reads the error cannot tell `Undelivered` from
`EffectUnknown` for them either. The emitter does stand at a call site that
knows whether it is on the send path or the receive path of the exchange it just
dispatched, so the position is recoverable — but only if the transport reports
it, and today it does not.

Three ways to close these, and this record does not choose among them because
each is a change to the capability and transport layers' surface rather than to
the feed:

- the emitter evaluates the same layered checks itself and records the layer it
  refused at, which keeps the error type untouched and duplicates the check
  order;
- the capability layer exposes the refusal layer as a typed value alongside the
  error, and the transport layer exposes the side of the wire alongside a budget
  error, which widens the `-api` vocabulary additively; or
- the budget case is avoided by not enumerating it, recording a single
  `BudgetExceeded` cause and placing the whole variant in `EffectUnknown`, which
  is safe for the inbound occurrence and conservatively wrong for the outbound
  one — a caller told to reconcile an attempt that never left the process is
  told to do unnecessary work, which is the acceptable direction to be wrong in.

The additive option is the better long-term shape and the first is the smaller
change. Each is acceptable to this record; what is not acceptable is an
implementation that derives the refusal cause from the request, that derives the
budget position from the variant alone, or that collapses several layers into
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
  inspector: one never reached a transport, the other reached the transport and
  was rejected before the peer saw it.
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
call, no more and no fewer, whether the call succeeds, is denied, or fails —
with one carve-out that the fail-closed rule forces and that is stated here
rather than left to be discovered: a check the feed itself refused produces **no**
entry. The feed could not record one, and fabricating or queueing it is what the
fail-closed rule below exists to prevent, so such a call is reported through the
health value and not through the feed. "Exactly one entry per call" therefore
holds for every call the feed admits and for no call it refuses.

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
- `NoSink` — the feed was constructed with no sink. This is a
  **construction-time posture**, not a runtime fault, and it is **decided once
  at construction and immutable for the feed's lifetime**: a feed built without
  a sink reports `NoSink` for its whole life and never becomes `Accepting` or
  `SinkFailed`. It is not a per-entry event, because there is no entry to lose:
  no destination was ever promised.
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

**A feed that was never given a sink has no fail-closed behaviour, and this
record cannot give it one.** The rule below protects a host that installed a
destination; a host that deliberately installed none has chosen no feed, and its
egress proceeds unrecorded by design rather than by fault. That is the correct
result of host ownership — this crate cannot insist on a sink it does not own —
but it means the guarantee is conditional on host configuration, and an Inspector
that reports a clean bill of health must be able to tell the two cases apart.
They are distinguishable only through the `NoSink` variant, which is why a
conforming host surfaces `health()` unconditionally rather than only on failure,
and why that surfacing is a requirement below rather than a convention.

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
3. The fault clears only when a record **succeeds**. Installing a working
   replacement sink and completing a record restores accepting behaviour without
   a process restart, and the bracket is handed to the Inspector so the gap is
   rendered rather than forgotten.

**Removing a failed sink does not clear the latch, and this is deliberate.**
The obvious alternative — treating removal as a return to the `NoSink` posture —
is rejected. It would discard `first_dropped_seq` and `last_dropped_seq`, and a
loud enumerable gap would become a state indistinguishable from a deliberate
no-audit configuration, which is precisely the indistinguishability this rule
exists to prevent. Worse, it would let the gap be erased by the one action that
is easiest to take: uninstall the destination. So removal leaves the feed
`SinkFailed` and still refusing; records keep being attempted and keep failing,
extending `last_dropped_seq`, until a sink is installed and a record succeeds.
The cost is that a host which removes its sink cannot restore service without
reinstalling one, and that is accepted: the host is the party that installed the
sink, so reinstalling one is within its own control and requires no capability
change and no restart.

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
variant. The justification is stated at the altitude where it is actually true,
because the obvious gloss for it is false.

**What `Offline` means today, re-derived from the code.** `NetworkError::Offline`
is a unit variant in a five-variant taxonomy, so it carries no reason at all, and
it is returned from more than one situation. Reading the construction sites in
this repository, it is returned for: a deny-all capability; a host outside the
allowlist; a capability check that **passed** while the backend owns no
transport; an unparseable or credentialed proxy URL, and separately a proxied
client that could not be built for a destination; an outgoing header name or
header value that fails to parse; an inbound response header whose value is not
visible text, which is reached only after a complete response has been received;
any non-timeout error from the HTTP client, which is the single catch-all for a
refused connection, a failed name resolution, a TLS failure, and a proxy
failure; an exhausted redirect budget; a peer close frame; a failure to spawn the
resolver thread; and a family of authority and URL parse failures in the
WebSocket path.

**So `Offline` does not mean that this backend performed no work.** Two of those
sites contradict the gloss outright. The exhausted redirect budget is reached
only after a full hop budget's worth of requests have already been sent and
their responses received — the hop-limit test runs after that hop is sent, not
before it — so several requests provably reached the peer and were acted on
before the variant was produced. And the non-timeout transport catch-all covers a
refused connection and a failed name resolution, both of which happen after a
socket was opened. `Offline` therefore does not distinguish "nothing happened"
from "a great deal happened and then the attempt was abandoned", and this record
must not claim that it does.

**What the reuse is justified by, at the site that produces it.** The feed's
refusal happens **at the capability check, before dispatch** — in exactly the
position where the check already refuses a deny-all capability, and before any
socket, resolution, or write. At that position "nothing was attempted" is true
whatever `Offline` means at the other positions, so reusing the variant adds no
new conflation _where it is raised_. The conflation it joins is pre-existing and
is between two network facts — an egress switch and a transport failure — not
between a network fact and a record-keeping fact. That is the whole of the
argument, and it is an argument about the raise site, not about the variant.

**What that costs, stated rather than glossed.** The distinction between "egress
is switched off" and "the audit feed is broken" does **not** stay visible in the
error channel. Adding a self-latching egress blackout makes the variant strictly
worse than the dozen-plus distinct situations already folded into it, for one
reason that
none of them shares: the new meaning has a character the others do not. It does
not clear on its own, only the host can clear it, and it persists across
unrelated requests. A caller that sees `Offline` can no longer assume the
condition is transient or network-shaped, and a monitoring consumer — which is
precisely the component the widening argument below is meant to protect — cannot
tell a switched-off network from a broken feed it is the only party able to
repair. This record accepts that cost, records it here so a later decision can
revisit it on evidence rather than on recollection, and does not freeze the
alternative. Four consequences follow, and each is a deliberate trade:

- **The network error taxonomy does not widen.** The existing variants —
  `Denied`, `Offline`, `Timeout`, `Budget`, `CountBudget` — are statements
  about the network. A record-keeping failure is not a network fact, and adding
  a variant for it would make a monitoring component's health a network failure
  reason, which is the conflation that makes "let a broken sink take down all
  networking" look reasonable. A dedicated variant remains possible and would
  need its own decision, because every consumer matches on this taxonomy; this
  record does not freeze it and does not grant it.
- **The distinction is carried by the health value, and reaching it is a
  requirement rather than a hope.** The plugin that called the request holds no
  sink and can fix no sink, so the error channel is an acceptable place for it
  to lose the distinction — but that is a reason the error channel may omit the
  distinction, not a reason the distinction exists somewhere else. It exists in
  `AuditFeedHealth`, which separates `NoSink` from `SinkFailed` and carries the
  bounded gap. That value is only useful if the host reads it, and nothing in
  this repository can make a host read it, so unconditional surfacing of
  `health()` is specified as a host obligation below rather than assumed here as
  a convention. A host that surfaces health only on failure cannot report the
  `NoSink` posture, and an Inspector that cannot see `NoSink` cannot tell a
  deliberate no-feed configuration from a working one.
- **The blast radius is bounded and loud.** Only the affected exchange and
  every check after it are refused, not the process; the fault is a latched,
  named condition with a bounded gap; and the recovery condition is explicit.
  The alternative — keep serving and count the loss — is rejected because an
  Inspector cannot distinguish a quiet period from a broken feed, which is the
  silent drop this rule exists to prevent.
- **The fail-closed behaviour is unchanged by the conflation.** Because the
  refusal happens before dispatch, a caller that receives `Offline` from a latched
  feed knows on this record's own terms that nothing left the process on its
  behalf, whatever else the variant may also mean. The conflation degrades the
  _diagnosis_ of a stopped request; it does not make a recorded-but-unattributable
  exchange look successful, which is the property the rule protects.

## Cardinality and redaction

The feed must not become an exfiltration channel: it is host-side, durable, and
reachable from plugin-controlled work, so anything a plugin can shape is a way
to write into a store the plugin does not own.

**No field is shaped to carry a credential, and one field cannot be ruled out.**
There is no URL field, no header field, no body field, no path field, no query
or fragment field, and no free-text field. For every field except `host` that
claim is structural rather than editorial: a credential has nowhere to go, which
is stronger than a rule saying credentials must be removed. `principal_id` is a
bounded handle from a closed alphabet, and it is chosen by the host rather than
by the requesting plugin, so a secret can only reach it through a host that
mints its handles badly — a host defect the minting contract forbids, and a
different failure mode from an exfiltration channel this crate's design opens.

`host` is the exception, and the exception is real, because `host` is the one
field whose bytes the requesting plugin shapes. The safe host alphabet admits
ASCII letters, digits, `.`, `-`, `_`, `~`, `%`, `:`, `[`, and `]`, and a length
check admits anything short. Neither test can detect secrecy, because secrecy is
not a property of a byte. A secret-shaped label is _inside_ the alphabet: an
unguessable random label used as a per-tenant or per-tunnel subdomain — the
shape a shared tunnel provider hands out so that only the holder of the name can
reach the tunnel — is drawn entirely from lowercase letters and digits, and the
feed would store it verbatim in a host-side durable store. So the residual is
stated rather than argued away: **the feed can keep a caller-chosen host string
that is itself a bearer token**, and neither the alphabet nor the length bound
nor the redaction form reduces that.

What does hold, and is worth being exact about, because it bounds the residual:

- Userinfo never reaches the host field. The redaction form drops it before the
  host is taken, so `user:secret@host` cannot smuggle a secret into `host`.
- Query and fragment never reach the feed at all, so a token in
  `?token=…` or `#…` cannot be carried by the host field either.
- The length bound caps the damage at a bounded number of bytes per entry, and
  the retention bounds cap the total.
- The host is the one field a **capability grant** already names. A host that is
  not granted is refused before an entry is built, so the feed only ever records
  hosts the operator has already allowed — which is a mitigation, not a fix: the
  operator granted a host and may not have realised the host string is a secret.

The control that would actually close the residual is a host-side rule about
_which_ granted hosts may be recorded — for example, refusing to record any host
under a domain the operator marks as carrying tenant-scoped unguessable labels.
That is a grant-layer policy, this repository does not own the grant layer's
policy surface, and this record does not decide it. The residual is accepted
with the reasoning above rather than closed, and an implementation review must
raise it again if the grant layer grows a notion of a secret-bearing host.

**The redacted URL is the one this repository already has.** Any URL that
reaches the feed boundary is passed through
`crates/bitty-network/src/diagnostics.rs::redacted_url` first, which yields
`scheme://host:port/path` with userinfo, query, and fragment dropped, an
unparseable input as `[redacted-url]`, and a control-bearing host as
`[invalid-host]`. The feed defines no second redaction form. Concretely,
`https://user:secret@example.com:8443/a?token=x#f` becomes
`https://example.com:8443/a`.

Those two placeholders describe what the redaction form yields in an **error
message**, and the feed stores neither of them. `safe_host` substitutes
`[invalid-host]` for an unvouchable host because a log line needs something
printable; the feed instead rejects such a host outright, for the reason given
under the bounds below. The two behaviours are deliberately different and the
difference is not an inconsistency: an error message that says `[invalid-host]`
has lost nothing a reader needed, while a durable audit entry that says
`[invalid-host]` has lost the attribution the feed exists to provide.

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
digits, `.`, `_`, `:`, and `-`. `host` is at most `MAX_HOST_BYTES` (253) bytes —
the DNS name limit — and must consist only of the safe host alphabet. A value
that violates any of these rules is a construction error, not a shortened value
and not a substituted placeholder.

Truncation is worse than rejection because of what it does to the key, and the
reason is the same for both string fields. Truncating `principal_id` would let
two distinct principals whose handles share a prefix collapse into one key, and
a merged key is precisely the attribution defect the key exists to prevent: a
denial recorded for one plugin becomes readable as a denial for another.

**The host field could have been given the opposite treatment, and the asymmetry
is named here because it is the obvious thing to do and was rejected rather than
assumed away.** The obvious design is to reject an out-of-alphabet `principal_id`
but _substitute_ the single constant `[invalid-host]` for every host outside the
alphabet, on the reasoning that a placeholder keeps the entry bounded where a
rejection would not. That is the same merge defect wearing a different hat: two
distinct hosts become one key component, and an Inspector asking "which host was
refused" gets an answer that is constant and therefore wrong for every host it
applies to. It is also the worse failure, not the milder one, because a
truncated `principal_id` at least keeps a distinguishing prefix while a constant
keeps nothing at all. A merge is a merge whether it comes from a prefix or from a
constant, so the host case is given the same treatment as the principal case —
**rejected** — and the asymmetry is removed rather than justified. The cost of
removing it is that an unvouchable host is not printable in a feed line at all,
which is the correct trade for a durable audit record.

**The length bound is a separate requirement with its own mechanism, not a
consequence of the alphabet check.** This is stated precisely because the
existing helper does not do it: `crates/bitty-network/src/diagnostics.rs::safe_host`
enforces exactly two things, that the host is non-empty and that every byte is in
the safe alphabet. It performs **no** length check, so it cannot be the mechanism
behind a byte ceiling, and an over-long alphabet-valid host passes straight
through it. `MAX_HOST_BYTES` is therefore specified here as this record's own
requirement, discharged by an explicit length test in the entry constructor
alongside the alphabet test, and covered by its own bound test. An implementation
that relies on the existing helper to bound the host length is non-conforming
even though it passes every alphabet test.

**A rejected host or principal is refused at the check, not recorded as a
degraded entry.** Rejection raises into the fail-closed rule: the entry cannot be
built, so the check is refused before dispatch and the condition surfaces through
the health value. This is why no placeholder constant appears in the feed's
vocabulary at all. The redaction placeholders still exist and still have their
documented behaviour in error messages, where a caller needs a printable
substitute; a durable audit record is held to a stricter rule than a log line,
because a log line that says `[invalid-host]` loses nothing while a feed entry
that says `[invalid-host]` loses the attribution the feed exists to provide.

**Cardinality is bounded by construction.** An entry is a fixed set of scalars
and closed enums plus two bounded strings, so its size has a constant ceiling.
This crate retains no history at all, so its cost per feed is O(1) and its cost
per entry is O(1). Everything that could grow without limit is either a bounded
counter or lives in the host's sink under the bounds below.

**Reconciling the issue's "no PII beyond host and port" clause with this entry.**
The clause and the entry disagree on their face, because the entry carries two
further datums, and the reconciliation is worth stating rather than leaving a
reader to notice the mismatch:

- `principal_id` is the only field that could carry identifying information about
  a plugin, and it is specified to be an opaque host-minted handle: not a plugin
  name, not a manifest path, and not anything the plugin supplies about itself.
  A handle is PII-free by construction _if_ the minting honours that. The
  minting contract is a host-side obligation that this repository does not own,
  so this record states it as a requirement and not as a guarantee the feed can
  enforce.
- `method` is the only other added datum. It is a member of a closed verb enum
  of seven values, carries no identifying information, and cannot be omitted
  without destroying the property the feed exists to serve: telling a
  non-idempotent attempt from an idempotent one is what makes "never retry
  blindly" actionable.

So the honest reading of the clause is that the feed adds no _request-derived_
identifying information beyond the destination — no path, no query, no header, no
body — and adds exactly one opaque plugin handle whose PII-freedom is a host
obligation, plus a closed verb enum. A stricter reading, in which no field beyond
host and port is permitted at all, would make the feed unable to attribute egress
to a plugin instance or to reason about idempotency, and this record does not
adopt it.

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
- The existing redaction vocabulary, including
  `crates/bitty-network/src/diagnostics.rs::redacted_url`,
  `crates/bitty-network/src/diagnostics.rs::safe_host`, and the three
  placeholders, together with its current-state claim that wiring those snapshots
  into the backends' error paths is a follow-up merge and not present today.
  What `safe_host` does and does not enforce — non-empty and alphabet, no length
  — was read from the helper itself, because the distinction decides whether the
  host length bound has a mechanism behind it.
- The agent runtime's tool-execution vocabulary, for the two-outcome property
  this record's outcome vocabulary is shaped around: a refusal that means no
  dispatch occurred, and an unknown effect that must be reconciled rather than
  retried.
- The merged direction decisions in this directory, by filename:
  `docs/decisions/26-server.md` (client-only by construction),
  `docs/decisions/27-quic.md` (QUIC as a direction marker),
  `docs/decisions/28-oauth.md` (OAuth deferral),
  `docs/decisions/29-proxy.md` (the `proxy` gate meaning),
  `docs/decisions/30-bridge.md` (the bridge boundary),
  `docs/decisions/24-pac.md` (PAC evaluation and proxy precedence), and
  `docs/decisions/21-tls-policy.md` (the TLS trust and identity contracts),
  whose redaction posture this record follows rather than restates.

### Findings

The main design risks were an audit gap that reads as a quiet period, an outcome
vocabulary that merges a denial with an uncertain effect, a feed that becomes a
side channel for plugin-controlled data, and a sink failure that is either
ignored or allowed to stop all networking. The decisions above address each one
explicitly: a latched health value with a bounded, enumerable gap that removing
the sink cannot erase; four outcome variants with a `may_have_had_effect`
predicate and a `Denied`/`Refused` invariant that is made unrepresentable by two
constructors with no field-wise alternative; no free-text field and rejection
instead of truncation or placeholder substitution; a feed-wide counter so the
emitter's own state stays O(1); and a fail-closed rule whose blast radius is one
exchange plus a repair.

**Four residual risks are accepted rather than closed, and each is stated where
it is decided rather than only here.**

1. **Two named implementation gaps in the error channel.** The refusal layer and
   the side of the wire on which a budget crossing was decided are both absent
   from the error types, and neither is recoverable by an emitter that reads only
   the error. Both are closable three ways, none chosen here.
2. **`host` can be a bearer token.** The alphabet and length checks cannot detect
   secrecy, and a secret-shaped tenant or tunnel subdomain is inside the safe
   alphabet. Mitigated by the grant already naming the host and by the retention
   bounds; not closed, because the control that would close it belongs to the
   grant layer's policy.
3. **`NetworkError::Offline` gains one more meaning among many.** The feed's
   fail-closed refusal reuses a unit variant that already covers a deny-all
   capability, an allowlist miss, an exhausted redirect budget reached after a
   full hop budget's worth of requests were already sent, a catch-all for refused
   connections and failed resolutions, and a dozen further situations enumerated
   where the reuse is decided. The distinction does not stay visible in the error
   channel. Accepted because the refusal is raised before dispatch, where nothing
   was attempted whatever the variant means elsewhere, and because the health
   value carries the distinction host-side; the cost is that the variant now
   includes a condition that is sticky and host-repairable, and it is recorded so
   a later widening decision can be made on evidence rather than on recollection.
4. **The fail-closed rule protects only a host that installed a sink.** A feed
   constructed without one serves unrecorded egress by design, because the sink
   is host-owned and this crate cannot insist on one. The only thing that makes
   the difference visible is the `NoSink` variant reaching the host, which is why
   unconditional surfacing of the health value is a requirement rather than a
   convention.

No audit controls were reviewed against an implementation, because no audit
vocabulary, sink, or emitter exists to review. Every requirement in this record,
including the constructor shape that makes the `Denied`/`Refused` invariant
structural, is **[specified, not implemented]**; nothing above is a delivered
property. This is a design-stage review of a specification, not an
implementation review and not an approval for third-party use.

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
3. The `Denied`/`Refused` invariant holds **by construction**, not by test: the
   entry exposes exactly the two constructors specified above, no field-wise or
   `Default` construction, and no constructor that takes a `decision`. A
   compile-level check proves the constructors are the only construction paths.
   Alongside that, vocabulary tests pin: `decision` is `Denied` if and only if
   `outcome` is `Refused`; `Refused` and `Undelivered` never report
   `may_have_had_effect`; `EffectUnknown` always does; `method` is `Some` if and
   only if `kind` is `Http`; every enum is exhaustively matchable with no
   wildcard arm. The tests are a regression pin against a later third
   constructor or a public field, and the record does not rely on them to make
   the invariant true.
4. The refusal cause is decided by a real signal, never derived from the
   request: a host miss, a port miss, a method miss, and a portless request
   each record their own `RefusedCause`, and a test proves those four are
   distinguishable from each other and from `Offline`. If the implementation
   takes the additive option above and widens the `-api` capability surface to
   expose the refusal layer, that widening is reviewed as its own vocabulary
   change.
5. The budget position is decided by a real signal, never inferred from the
   error variant: a test proves that the same variant raised on the send path
   records an `Undelivered` budget cause and the same variant raised on the
   receive path records an `EffectUnknown` budget cause, that an inbound budget
   crossing is never recorded as `Completed`, and that an inbound crossing is
   never recorded as `Undelivered`. Whichever of the three closing options the
   implementation takes is stated in the implementation's own documentation,
   including the consequence of the third — that an outbound crossing is
   conservatively recorded as uncertain.
6. Fail-closed tests prove: a feed constructed with no sink reports `NoSink` for
   its whole life and never reports `Accepting` or `SinkFailed`; a sink that
   returns an error latches `SinkFailed`; the exchange whose entry could not be
   recorded does not proceed and yields no fabricated entry; every later check
   is refused before dispatch while latched; `first_dropped_seq` and
   `last_dropped_seq` bracket the gap exactly; **removing a latched sink leaves
   the feed `SinkFailed` and still refusing, and preserves the bracket** rather
   than reverting to `NoSink`; and a subsequent successful record through a
   working replacement sink restores accepting behaviour with no process restart
   and hands the bracket to the Inspector.
7. The host surfaces the health value **unconditionally**, not only on failure: a
   conforming host reads `health()` on a schedule and at Inspector open, so that
   the `NoSink` posture and a latched `SinkFailed` are both reachable by a
   consumer that never saw an error. This is specified as a requirement because
   the distinction between "no feed by configuration" and "working feed" is
   carried by this value alone, and nothing in this repository can make a host
   read it.
8. Exactly-one-entry tests prove one entry per `NetworkService` call across
   success, denial, and transport failure **for every call the feed admits**;
   that a call the feed itself refused produces no entry and is reported through
   the health value instead; that `seq` is monotonic across the feed and equals
   dispatch order; that entries under one key keep their `seq` order; and that a
   cross-host redirect yields two entries under two keys.
9. Redaction tests prove that a canary credential in a userinfo position, a
   query, a fragment, and a header value appears in no entry, in no `Debug` or
   `Display` output, and in no serialized form; that a rendered line is composed
   from `host` and `port` only, carrying neither a scheme nor a path, so it
   matches neither a stored URL nor the wider `redacted_url` form; and that the
   feed stores no path. A canary in a **userinfo** position is dropped before the
   host is taken, and a test proves the userinfo secret does not survive into the
   `host` field.
10. Bound tests prove that an over-long or out-of-alphabet `principal_id` is
    rejected rather than truncated or replaced; that two handles sharing a prefix
    cannot collapse into one key; that an over-long host is **rejected**, by an
    explicit length test in the constructor and not by any alphabet check, since
    an alphabet-valid over-long host must be shown to fail; that an
    out-of-alphabet host is **rejected** rather than recorded as a placeholder;
    that no placeholder constant appears in any recorded entry; that each
    rejection refuses the check and produces no entry; and that a conforming
    sink honours both retention bounds, evicts oldest-first, and increments its
    eviction count.
11. The plugin-identity handoff is specified on the host side: how
    `principal_id` is minted, its stability scope, what a consumer must do across
    a host restart, and the minting obligation that the handle be opaque and
    carry no identifying information, since the feed's compliance with the issue's
    data-minimisation clause depends on it. This repository does not own that
    contract and does not decide it here.
12. The Network Inspector surface that reads the feed is scoped, specified,
    and reviewed as its own work. This repository ships the feed, not the
    Inspector.
13. Implementation-level security review before any third-party use, covering
    the fail-closed rule under a hostile or full sink, the redaction boundary
    under a hostile host, the retention bounds under a flood, the `Offline`
    conflation recorded above, and the case of a host that never installs a sink.

A proposal that adds a free-text field, an unbounded retained field, a second
redaction form, a placeholder substitution in place of a rejection, a buffered
queue with a drop policy inside this crate, or a silent drop returns for a new
decision rather than being folded into this one.
