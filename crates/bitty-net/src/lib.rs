//! `bitty-net`: the Bitty native network component.
//!
//! A single-purpose stdio coprocess (DIR-030): the Bitty core spawns it on
//! first use, speaks wire protocol v1 ([`bitty_network_wire`]) over its
//! stdin/stdout, and closes stdin when idle. The component is mechanism only:
//! the core is the policy authority and hands a [`Grant`] with every request;
//! the component re-checks that grant before any socket work and never
//! widens it (an empty grant is offline).
//!
//! The binary is a thin wrapper around [`serve`], which is generic over the
//! input, the output, and the [`Backend`] so the protocol engine is testable
//! with a fake backend. [`HttpBackend`] is the production backend over
//! `bitty-network`'s [`HttpNetworkService`].
//!
//! # Session
//!
//! 1. The first frame must be `Hello`; the component answers `HelloAck` with
//!    the highest version in `[min, max] ∩ [PROTOCOL_VERSION,
//!    PROTOCOL_VERSION]`. A different first message, a component-name
//!    mismatch, or an empty intersection answers a connection-level
//!    `Error { id: CONNECTION_ID, kind: protocol }` and ends the session with
//!    [`ServeOutcome::ProtocolError`].
//! 2. `HttpRequest` starts a request. With `body_follows` the body arrives in
//!    `RequestBody` chunks (bounded by [`MAX_REQUEST_BODY_BYTES`]) and the
//!    request runs after the `last` chunk. At most `MAX_IN_FLIGHT` requests
//!    run concurrently, each on its own worker thread; the answer is
//!    `ResponseHead` plus `ResponseBody` chunks of at most
//!    `MAX_BODY_CHUNK_BYTES` (the final one has `last = true`), or one
//!    `Error`.
//! 3. `Cancel` abandons a request: no further frame for that id leaves the
//!    component after the cancel is processed. Frames already in the pipe
//!    may still arrive, so the core drops frames for ids it cancelled.
//!    `Cancel` and `RequestBody` for unknown ids are ignored (they race with
//!    completion).
//! 4. A duplicate in-flight id answers `Error { kind: protocol }` for that id
//!    and leaves the original request untouched. Exceeding the in-flight
//!    limit or the request body bound answers `Error { kind: budget }`.
//! 5. Any undecodable frame after the handshake (unknown tag, malformed
//!    payload, oversize length) or a message in the wrong direction answers
//!    a connection-level protocol error and closes the session.
//! 6. `Shutdown` or stdin EOF stops accepting requests, waits up to
//!    [`ServeConfig::shutdown_grace`] for running requests, abandons the rest,
//!    and returns.
//!
//! All output is serialized through one writer thread. Diagnostics go to
//! stderr only and never include URLs, header values, or bodies.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::io::{BufWriter, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use bitty_network::{HttpNetworkService, NetworkService};
use bitty_network_api::{HttpMethod, NetworkCapability, NetworkError, Request, Response};
use bitty_network_wire::{
    CONNECTION_ID, ErrorKind, FrameReader, Grant, MAX_BODY_CHUNK_BYTES, MAX_IN_FLIGHT,
    MAX_REQUEST_BODY_BYTES, Message, Method, PROTOCOL_VERSION, WireError, encode, encode_frame,
};

/// Component name announced in `HelloAck` and expected in `Hello`.
pub const COMPONENT_NAME: &str = "net";

/// Component version announced in `HelloAck`.
pub const COMPONENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default grace for running requests after `Shutdown` or stdin EOF.
///
/// Shorter than the core's 2 s kill deadline so a clean exit wins the race.
pub const SHUTDOWN_GRACE: Duration = Duration::from_millis(1500);

/// Capacity of the outbound frame queue between workers and the writer.
///
/// Bounded so a stalled reader of stdout applies backpressure to workers
/// instead of letting queued response chunks grow without limit.
pub const OUTBOUND_QUEUE_FRAMES: usize = 2 * MAX_IN_FLIGHT;

/// Process exit code for a clean end (EOF or `Shutdown`).
pub const EXIT_OK: u8 = 0;
/// Process exit code when stdin or stdout failed.
pub const EXIT_IO: u8 = 1;
/// Process exit code for a protocol violation by the peer.
pub const EXIT_PROTOCOL: u8 = 2;

/// Executes one capability-checked request.
///
/// [`serve`] has already verified `request` against `capability` with
/// [`NetworkCapability::check_request`]; implementations must enforce the
/// same capability again on every hop they make (redirects included) and
/// must never widen it.
pub trait Backend: Send + Sync + 'static {
    /// Execute `request` under `capability`.
    fn execute(
        &self,
        capability: &NetworkCapability,
        request: &Request,
    ) -> Result<Response, NetworkError>;
}

/// Production backend: one [`HttpNetworkService`] per request, built from the
/// request's own capability (direct egress; proxy inheritance only when the
/// `bitty-network` `proxy` feature is enabled).
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpBackend;

impl Backend for HttpBackend {
    fn execute(
        &self,
        capability: &NetworkCapability,
        request: &Request,
    ) -> Result<Response, NetworkError> {
        HttpNetworkService::new(capability.clone()).request(request)
    }
}

/// Tunables for [`serve`].
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// Grace for running requests after `Shutdown` or EOF.
    pub shutdown_grace: Duration,
    /// Concurrent request limit; clamped to `MAX_IN_FLIGHT`.
    pub max_in_flight: usize,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            shutdown_grace: SHUTDOWN_GRACE,
            max_in_flight: MAX_IN_FLIGHT,
        }
    }
}

/// How a [`serve`] session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeOutcome {
    /// Input reached EOF at a frame boundary.
    Eof,
    /// The peer sent `Shutdown`.
    Shutdown,
    /// The peer violated the protocol; a connection-level error was sent.
    ProtocolError,
    /// Reading input failed with an I/O error.
    InputError,
    /// Writing output failed (the peer is gone).
    OutputClosed,
}

impl ServeOutcome {
    /// Process exit code for this outcome.
    #[must_use]
    pub fn exit_code(self) -> u8 {
        match self {
            ServeOutcome::Eof | ServeOutcome::Shutdown => EXIT_OK,
            ServeOutcome::ProtocolError => EXIT_PROTOCOL,
            ServeOutcome::InputError | ServeOutcome::OutputClosed => EXIT_IO,
        }
    }
}

/// Write one diagnostic line to stderr (never URLs, header values, bodies).
fn log(args: fmt::Arguments<'_>) {
    eprintln!("bitty-net: {args}");
}

/// Map a wire method onto the API vocabulary.
#[must_use]
pub fn api_method(method: Method) -> HttpMethod {
    match method {
        Method::Get => HttpMethod::Get,
        Method::Post => HttpMethod::Post,
        Method::Put => HttpMethod::Put,
        Method::Delete => HttpMethod::Delete,
        Method::Head => HttpMethod::Head,
        Method::Options => HttpMethod::Options,
        Method::Patch => HttpMethod::Patch,
    }
}

/// Default port of `url`'s scheme (`443` for `https`/`wss`, `80` for
/// `http`/`ws`), or `None` for any other or missing scheme.
fn scheme_default_port(url: &str) -> Option<u16> {
    let (scheme, _) = url.split_once("://")?;
    match scheme.to_ascii_lowercase().as_str() {
        "https" | "wss" => Some(443),
        "http" | "ws" => Some(80),
        _ => None,
    }
}

/// Build the narrowest [`NetworkCapability`] expressing `grant` for a request
/// to `url`.
///
/// No hosts is offline. A host with listed ports allows exactly those ports;
/// a host with no ports allows only the default port of `url`'s scheme (and
/// nothing when the scheme has none). A method mask restricts methods; a
/// zero mask allows none. The result is never wider than the grant.
#[must_use]
pub fn capability_from_grant(grant: &Grant, url: &str) -> NetworkCapability {
    let mut capability = NetworkCapability::offline();
    if grant.hosts.is_empty() {
        return capability;
    }
    let default_port = scheme_default_port(url);
    for entry in &grant.hosts {
        capability = if entry.ports.is_empty() {
            capability.with_domain_ports(entry.host.clone(), default_port)
        } else {
            capability.with_domain_ports(entry.host.clone(), entry.ports.iter().copied())
        };
    }
    if let Some(mask) = grant.methods {
        capability = capability.restrict_methods(Method::in_mask(mask).map(api_method));
    }
    capability
}

/// Map a backend failure onto a wire error kind plus a redacted message.
#[must_use]
pub fn error_kind(error: &NetworkError) -> ErrorKind {
    match error {
        NetworkError::Denied { .. } => ErrorKind::Denied,
        NetworkError::Offline => ErrorKind::Offline,
        NetworkError::Timeout { .. } => ErrorKind::Timeout,
        NetworkError::Budget { .. } | NetworkError::CountBudget { .. } => ErrorKind::Budget,
        NetworkError::Tls { .. } => ErrorKind::Tls,
    }
}

/// One frame queued for the writer, with the cancel flag of its request.
struct Outbound {
    message: Message,
    cancel: Option<Arc<AtomicBool>>,
}

/// Command for the writer thread.
enum WriterCmd {
    Frame(Outbound),
    Stop,
}

/// Per-id state of an admitted request.
enum Entry {
    /// Waiting for `RequestBody` chunks.
    Collecting(Box<Pending>),
    /// Executing on a worker thread.
    Running { cancel: Arc<AtomicBool> },
}

/// A request admitted with `body_follows`, waiting for its last chunk.
struct Pending {
    capability: NetworkCapability,
    request: Request,
}

/// State shared between the reader and the workers.
struct Shared {
    entries: Mutex<HashMap<u64, Entry>>,
    idle: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Writer thread body: encode and write frames in order, flushing whenever
/// the queue drains; frames of cancelled requests are dropped here.
fn writer_loop<W: Write>(output: W, rx: Receiver<WriterCmd>, failed: Arc<AtomicBool>) {
    let mut out = BufWriter::new(output);
    let write = |out: &mut BufWriter<W>, frame: Outbound| -> bool {
        if frame
            .cancel
            .as_ref()
            .is_some_and(|cancel| cancel.load(Ordering::SeqCst))
        {
            return true;
        }
        match encode_frame(&frame.message) {
            Ok(bytes) => out.write_all(&bytes).is_ok(),
            Err(error) => {
                log(format_args!("dropped unencodable frame: {error}"));
                true
            }
        }
    };
    'outer: while let Ok(cmd) = rx.recv() {
        let mut next = Some(cmd);
        while let Some(cmd) = next.take() {
            match cmd {
                WriterCmd::Stop => break 'outer,
                WriterCmd::Frame(frame) => {
                    if !write(&mut out, frame) {
                        failed.store(true, Ordering::SeqCst);
                        return;
                    }
                }
            }
            next = rx.try_recv().ok();
        }
        if out.flush().is_err() {
            failed.store(true, Ordering::SeqCst);
            return;
        }
    }
    if out.flush().is_err() {
        failed.store(true, Ordering::SeqCst);
    }
}

/// Reader-side session state.
struct Session<B: Backend> {
    shared: Arc<Shared>,
    tx: SyncSender<WriterCmd>,
    backend: Arc<B>,
    max_in_flight: usize,
}

impl<B: Backend> Session<B> {
    /// Queue one frame not tied to a cancellable request.
    fn send(&self, message: Message) {
        let _ = self.tx.send(WriterCmd::Frame(Outbound {
            message,
            cancel: None,
        }));
    }

    fn send_error(&self, id: u64, kind: ErrorKind, message: impl Into<String>) {
        self.send(Message::Error {
            id,
            kind,
            message: message.into(),
        });
    }

    /// Admit one `HttpRequest`.
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the wire message fields one to one"
    )]
    fn on_request(
        &self,
        id: u64,
        plugin_id: &str,
        grant: &Grant,
        method: Method,
        url: String,
        headers: Vec<(String, String)>,
        timeout_ms: u32,
        max_body_bytes: u64,
        body_follows: bool,
    ) {
        let mut entries = self.shared.lock();
        if entries.contains_key(&id) {
            drop(entries);
            log(format_args!("request {id}: duplicate in-flight id"));
            self.send_error(id, ErrorKind::Protocol, "duplicate in-flight request id");
            return;
        }
        if entries.len() >= self.max_in_flight {
            drop(entries);
            log(format_args!("request {id}: in-flight limit reached"));
            self.send_error(id, ErrorKind::Budget, "too many requests in flight");
            return;
        }
        let capability = capability_from_grant(grant, &url);
        let request = Request {
            method: api_method(method),
            url,
            headers,
            body: Vec::new(),
            timeout: (timeout_ms > 0).then(|| Duration::from_millis(u64::from(timeout_ms))),
            max_body_bytes: (max_body_bytes > 0).then_some(max_body_bytes),
        };
        if let Err(error) = capability.check_request(&request) {
            drop(entries);
            log(format_args!(
                "request {id} (plugin {plugin_id}): refused by grant ({})",
                error_kind(&error)
            ));
            self.send_error(id, error_kind(&error), error.to_string());
            return;
        }
        if body_follows {
            entries.insert(
                id,
                Entry::Collecting(Box::new(Pending {
                    capability,
                    request,
                })),
            );
        } else {
            self.start(&mut entries, id, capability, request);
        }
    }

    /// Append one `RequestBody` chunk; start the request on `last`.
    fn on_body(&self, id: u64, data: &[u8], last: bool) {
        let mut entries = self.shared.lock();
        match entries.get_mut(&id) {
            None => {}
            Some(Entry::Running { cancel }) => {
                cancel.store(true, Ordering::SeqCst);
                drop(entries);
                log(format_args!("request {id}: body chunk after body end"));
                self.send_error(id, ErrorKind::Protocol, "request body after last chunk");
            }
            Some(Entry::Collecting(pending)) => {
                let total = u64::try_from(pending.request.body.len().saturating_add(data.len()))
                    .unwrap_or(u64::MAX);
                if total > MAX_REQUEST_BODY_BYTES {
                    entries.remove(&id);
                    drop(entries);
                    log(format_args!("request {id}: request body over budget"));
                    self.send_error(
                        id,
                        ErrorKind::Budget,
                        format!("request body exceeds {MAX_REQUEST_BODY_BYTES} bytes"),
                    );
                    return;
                }
                pending.request.body.extend_from_slice(data);
                if last {
                    if let Some(Entry::Collecting(pending)) = entries.remove(&id) {
                        let Pending {
                            capability,
                            request,
                        } = *pending;
                        self.start(&mut entries, id, capability, request);
                    }
                }
            }
        }
    }

    /// Abandon one request (unknown ids are ignored).
    fn on_cancel(&self, id: u64) {
        let mut entries = self.shared.lock();
        match entries.get(&id) {
            Some(Entry::Collecting(_)) => {
                entries.remove(&id);
                self.shared.idle.notify_all();
            }
            Some(Entry::Running { cancel }) => cancel.store(true, Ordering::SeqCst),
            None => {}
        }
    }

    /// Mark `id` running and hand it to a worker thread.
    fn start(
        &self,
        entries: &mut HashMap<u64, Entry>,
        id: u64,
        capability: NetworkCapability,
        request: Request,
    ) {
        let cancel = Arc::new(AtomicBool::new(false));
        entries.insert(
            id,
            Entry::Running {
                cancel: Arc::clone(&cancel),
            },
        );
        let worker = Worker {
            id,
            shared: Arc::clone(&self.shared),
            tx: self.tx.clone(),
            backend: Arc::clone(&self.backend),
            cancel,
        };
        let spawned = thread::Builder::new()
            .name(format!("bitty-net-req-{id}"))
            .spawn(move || worker.run(&capability, &request));
        if spawned.is_err() {
            entries.remove(&id);
            log(format_args!("request {id}: worker spawn failed"));
            self.send_error(id, ErrorKind::Internal, "worker unavailable");
        }
    }

    /// Stop accepting, wait up to `grace` for running requests, then abandon
    /// whatever is left.
    fn drain(&self, grace: Duration) {
        let mut entries = self.shared.lock();
        entries.retain(|_, entry| matches!(entry, Entry::Running { .. }));
        let (mut entries, _) = self
            .shared
            .idle
            .wait_timeout_while(entries, grace, |entries| !entries.is_empty())
            .unwrap_or_else(PoisonError::into_inner);
        if !entries.is_empty() {
            log(format_args!(
                "abandoning {} request(s) after shutdown grace",
                entries.len()
            ));
        }
        for entry in entries.values() {
            if let Entry::Running { cancel } = entry {
                cancel.store(true, Ordering::SeqCst);
            }
        }
        entries.clear();
    }
}

/// One request executing on its own thread.
struct Worker<B: Backend> {
    id: u64,
    shared: Arc<Shared>,
    tx: SyncSender<WriterCmd>,
    backend: Arc<B>,
    cancel: Arc<AtomicBool>,
}

impl<B: Backend> Worker<B> {
    fn run(self, capability: &NetworkCapability, request: &Request) {
        if !self.cancelled() {
            let result = catch_unwind(AssertUnwindSafe(|| {
                self.backend.execute(capability, request)
            }));
            match result {
                Ok(Ok(response)) => self.respond(response),
                Ok(Err(error)) => {
                    self.emit(Message::Error {
                        id: self.id,
                        kind: error_kind(&error),
                        message: error.to_string(),
                    });
                }
                Err(_) => {
                    log(format_args!("request {}: backend panicked", self.id));
                    self.emit(Message::Error {
                        id: self.id,
                        kind: ErrorKind::Internal,
                        message: "internal backend failure".to_owned(),
                    });
                }
            }
        }
        // Retire the id only after every frame is queued, so the drain's
        // final `Stop` lands behind them in the writer queue.
        let mut entries = self.shared.lock();
        if let Some(Entry::Running { cancel }) = entries.get(&self.id) {
            if Arc::ptr_eq(cancel, &self.cancel) {
                entries.remove(&self.id);
            }
        }
        self.shared.idle.notify_all();
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    /// Queue one frame; false once cancelled or the writer is gone.
    fn emit(&self, message: Message) -> bool {
        if self.cancelled() {
            return false;
        }
        self.tx
            .send(WriterCmd::Frame(Outbound {
                message,
                cancel: Some(Arc::clone(&self.cancel)),
            }))
            .is_ok()
    }

    /// Send the head plus bounded body chunks (`last` on the final one).
    fn respond(&self, response: Response) {
        let head = Message::ResponseHead {
            id: self.id,
            status: response.status,
            headers: response.headers,
        };
        if let Err(error) = encode(&head) {
            log(format_args!(
                "request {}: response head outside wire limits ({error})",
                self.id
            ));
            self.emit(Message::Error {
                id: self.id,
                kind: ErrorKind::Budget,
                message: "response headers exceed wire limits".to_owned(),
            });
            return;
        }
        if !self.emit(head) {
            return;
        }
        let body = response.body;
        if body.is_empty() {
            self.emit(Message::ResponseBody {
                id: self.id,
                data: Vec::new(),
                last: true,
            });
            return;
        }
        let chunks = body.len().div_ceil(MAX_BODY_CHUNK_BYTES);
        for (index, chunk) in body.chunks(MAX_BODY_CHUNK_BYTES).enumerate() {
            let sent = self.emit(Message::ResponseBody {
                id: self.id,
                data: chunk.to_vec(),
                last: index + 1 == chunks,
            });
            if !sent {
                return;
            }
        }
    }
}

/// Negotiate the protocol version for a `Hello { min, max }` offer.
///
/// Returns the highest version both sides support, or `None` when the
/// ranges do not intersect (or the offer is inverted).
#[must_use]
pub fn negotiate(min: u16, max: u16) -> Option<u16> {
    let low = min.max(PROTOCOL_VERSION);
    let high = max.min(PROTOCOL_VERSION);
    (min <= max && low <= high).then_some(high)
}

/// Serve one component session from `input` to `output` with `backend`.
///
/// Blocks until EOF, `Shutdown`, a protocol violation, or an I/O failure,
/// then drains running requests within [`ServeConfig::shutdown_grace`] and
/// stops the writer. See the [crate docs](crate) for the session rules.
pub fn serve<R, W, B>(input: R, output: W, backend: Arc<B>, config: &ServeConfig) -> ServeOutcome
where
    R: Read,
    W: Write + Send + 'static,
    B: Backend,
{
    let (tx, rx) = sync_channel(OUTBOUND_QUEUE_FRAMES);
    let failed = Arc::new(AtomicBool::new(false));
    let writer_failed = Arc::clone(&failed);
    let writer = thread::Builder::new()
        .name("bitty-net-writer".to_owned())
        .spawn(move || writer_loop(output, rx, writer_failed));
    let Ok(writer) = writer else {
        log(format_args!("writer thread spawn failed"));
        return ServeOutcome::OutputClosed;
    };
    let session = Session {
        shared: Arc::new(Shared {
            entries: Mutex::new(HashMap::new()),
            idle: Condvar::new(),
        }),
        tx,
        backend,
        max_in_flight: config.max_in_flight.clamp(1, MAX_IN_FLIGHT),
    };
    let mut reader = FrameReader::new(input);

    let outcome = match handshake(&session, &mut reader) {
        Some(outcome) => outcome,
        None => run(&session, &mut reader, &failed),
    };

    session.drain(config.shutdown_grace);
    let _ = session.tx.send(WriterCmd::Stop);
    let _ = writer.join();
    if failed.load(Ordering::SeqCst) && outcome != ServeOutcome::ProtocolError {
        return ServeOutcome::OutputClosed;
    }
    outcome
}

/// Map a decode failure to the session outcome, sending the
/// connection-level protocol error where the peer is at fault.
fn read_failure<B: Backend>(session: &Session<B>, error: &WireError) -> ServeOutcome {
    match error {
        WireError::Io(kind) => {
            log(format_args!("input failed: {kind}"));
            ServeOutcome::InputError
        }
        other => {
            log(format_args!("protocol violation: {other}"));
            session.send_error(CONNECTION_ID, ErrorKind::Protocol, other.to_string());
            ServeOutcome::ProtocolError
        }
    }
}

/// Run the handshake; `Some(outcome)` ends the session early.
fn handshake<R: Read, B: Backend>(
    session: &Session<B>,
    reader: &mut FrameReader<R>,
) -> Option<ServeOutcome> {
    let protocol_error = |message: &str| {
        log(format_args!("handshake refused: {message}"));
        session.send_error(CONNECTION_ID, ErrorKind::Protocol, message);
        Some(ServeOutcome::ProtocolError)
    };
    match reader.read_message() {
        Ok(None) => Some(ServeOutcome::Eof),
        Err(error) => Some(read_failure(session, &error)),
        Ok(Some(Message::Hello {
            min,
            max,
            component,
            ..
        })) => {
            if component != COMPONENT_NAME {
                return protocol_error("component name mismatch");
            }
            match negotiate(min, max) {
                Some(protocol) => {
                    session.send(Message::HelloAck {
                        protocol,
                        component: COMPONENT_NAME.to_owned(),
                        version: COMPONENT_VERSION.to_owned(),
                    });
                    None
                }
                None => protocol_error("unsupported protocol version"),
            }
        }
        Ok(Some(_)) => protocol_error("handshake required before any other message"),
    }
}

/// Post-handshake message loop.
fn run<R: Read, B: Backend>(
    session: &Session<B>,
    reader: &mut FrameReader<R>,
    failed: &AtomicBool,
) -> ServeOutcome {
    loop {
        if failed.load(Ordering::SeqCst) {
            return ServeOutcome::OutputClosed;
        }
        let message = match reader.read_message() {
            Ok(Some(message)) => message,
            Ok(None) => return ServeOutcome::Eof,
            Err(error) => return read_failure(session, &error),
        };
        match message {
            Message::HttpRequest {
                id,
                plugin_id,
                grant,
                method,
                url,
                headers,
                timeout_ms,
                max_body_bytes,
                body_follows,
            } => session.on_request(
                id,
                &plugin_id,
                &grant,
                method,
                url,
                headers,
                timeout_ms,
                max_body_bytes,
                body_follows,
            ),
            Message::RequestBody { id, data, last } => session.on_body(id, &data, last),
            Message::Cancel { id } => session.on_cancel(id),
            Message::Shutdown => return ServeOutcome::Shutdown,
            other => {
                log(format_args!(
                    "protocol violation: unexpected message tag 0x{:02x}",
                    other.tag()
                ));
                session.send_error(
                    CONNECTION_ID,
                    ErrorKind::Protocol,
                    "unexpected message for this direction or phase",
                );
                return ServeOutcome::ProtocolError;
            }
        }
    }
}

#[cfg(test)]
mod tests;
