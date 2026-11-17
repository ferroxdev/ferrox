//! xray's sender-side mux carrier pool: one underlayer per `MaxConcurrency` flows, a serialized
//! writer under it, and a demux that hands each session's replies to its own flow.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use ferrox_core::mux::{self, NewTail};

/// The reference's `MaxConnection`: a carrier is retired after this many sessions and a fresh one
/// dialed for the sessions that follow, while the flows it already carries drain.
pub(crate) const LIFETIME: usize = 1024;

/// The reference's worker monitor: a carrier with no sessions whose last pick or close is older
/// than this is retired, so an idle pool does not hold its underlayer open.
const IDLE: Duration = Duration::from_secs(16);

/// The reference's `Dispatch` retries a pick this many times when the last slot fills under it.
const PICKS: usize = 16;

/// One flow's reply queue; a flow that cannot keep up is ended without stalling the demux.
const REPLIES: usize = 64;

/// A carrier's two halves and the close that tears its socket down.
pub(crate) struct Uplink {
    pub(crate) read: Box<dyn Read + Send>,
    pub(crate) write: Box<dyn Write + Send>,
    pub(crate) close: Arc<dyn Fn() + Send + Sync>,
}

/// What one demuxed frame hands its flow.
pub(crate) struct Msg {
    pub(crate) data: Vec<u8>,
    pub(crate) end: bool,
}

/// One TCP session on a carrier.
pub(crate) struct Flow {
    carrier: Arc<Carrier>,
    id: u16,
    replies: Option<Receiver<Msg>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl Flow {
    /// One bulk `Keep`; the carrier's writer lock keeps concurrent sessions from interleaving and
    /// the whole payload leaves in one vectored write.
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        self.carrier.keep(self.id, data)
    }

    /// Hands the reply lane to the downlink worker while this handle keeps the writer.
    pub(crate) fn take_replies(&mut self) -> Option<Receiver<Msg>> {
        self.replies.take()
    }

    pub(crate) fn end_upload(&self) {
        if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        self.carrier
            .frame(self.id, mux::Status::End, 0, None, None, &[]);
    }

    pub(crate) fn release(self) {
        self.carrier.release(self.id);
    }

    pub(crate) fn close(self) {
        // End is on the wire before the id returns to the table; the writer lock orders every frame.
        self.end_upload();
        self.carrier.release(self.id);
    }
}

/// One datagram session; its replies go to the association's own relay socket.
pub(crate) struct UdpFlow {
    carrier: Arc<Carrier>,
    id: u16,
    ended: Arc<std::sync::atomic::AtomicBool>,
}

impl UdpFlow {
    pub(crate) fn send(&self, target: &mux::Target<'_>, data: &[u8]) -> bool {
        if self.ended.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        self.carrier.frame(
            self.id,
            mux::Status::Keep,
            mux::DATA,
            Some(*target),
            None,
            data,
        )
    }

    pub(crate) fn close(self) {
        // Same order as `Flow::close`: the End write returns before the id is released.
        if !self.ended.load(std::sync::atomic::Ordering::Relaxed) {
            self.carrier
                .frame(self.id, mux::Status::End, 0, None, None, &[]);
        }
        self.carrier.release(self.id);
    }
}

pub(crate) type Deliver = Arc<dyn Fn(&[u8], Option<SocketAddr>) + Send + Sync>;

#[derive(Clone)]
enum Sink {
    Tcp(SyncSender<Msg>, Arc<std::sync::atomic::AtomicBool>),
    Udp(Deliver, Arc<std::sync::atomic::AtomicBool>),
}

/// Frames one bulk `Keep` leaves in a single vectored write: a 32 KiB upload read is four frames
/// and one syscall where it used to be four writes, and no payload byte moves.
const BATCH: usize = 4;

/// The segments one batch hands the kernel: a head and a payload part for each frame.
const BATCH_PARTS: usize = 2 * BATCH;

/// The empty segment a parts list starts from, overwritten by every frame it holds.
const NO_PART: &[u8] = &[];

struct Writer {
    out: Box<dyn Write + Send>,
    header: Vec<u8>,
    heads: Vec<u8>,
}

impl Writer {
    fn frame(
        &mut self,
        id: u16,
        status: mux::Status,
        options: u8,
        target: Option<mux::Target<'_>>,
        global_id: Option<[u8; mux::GLOBAL_ID]>,
        data: &[u8],
    ) -> bool {
        let frame = mux::Outgoing {
            id,
            status,
            options,
            target,
            global_id,
        };
        let at = frame.encode_header_into(&mut self.header);
        if options & mux::DATA == 0 {
            self.header.truncate(at);
            return crate::proxy::write_all_parts::<2>(&mut *self.out, &[&self.header[..], &[]])
                .is_ok();
        }
        frame.patch_payload_len(&mut self.header, at, data.len());
        crate::proxy::write_all_parts::<2>(&mut *self.out, &[&self.header[..], data]).is_ok()
    }

    /// A bulk `Keep`: the payload split into frame-sized chunks, every head encoded ahead of the
    /// write so the chunks leave as one vectored call. The heads are eight bytes each; the payload
    /// goes to the kernel from where it was read, never through `heads`.
    fn keep(&mut self, id: u16, data: &[u8]) -> bool {
        let keep = mux::Outgoing::bare(id, mux::Status::Keep, mux::DATA);
        let mut rest = data;
        loop {
            let take = rest.len().min(BATCH * mux::CHUNK_MAX);
            let (batch, tail) = rest.split_at(take);
            if !self.keep_batch(&keep, batch) {
                return false;
            }
            if tail.is_empty() {
                return true;
            }
            rest = tail;
        }
    }

    fn keep_batch(&mut self, keep: &mux::Outgoing<'_>, batch: &[u8]) -> bool {
        self.heads.clear();
        let mut payloads: [&[u8]; BATCH] = [NO_PART; BATCH];
        let mut spans = [(0usize, 0usize); BATCH];
        let mut frames = 0usize;
        let mut rest = batch;
        loop {
            let take = rest.len().min(mux::CHUNK_MAX);
            let (chunk, tail) = rest.split_at(take);
            let at = keep.encode_header_into(&mut self.header);
            keep.patch_payload_len(&mut self.header, at, chunk.len());
            let start = self.heads.len();
            self.heads.extend_from_slice(&self.header);
            spans[frames] = (start, self.heads.len());
            payloads[frames] = chunk;
            frames += 1;
            if tail.is_empty() {
                break;
            }
            rest = tail;
        }
        let mut parts: [&[u8]; BATCH_PARTS] = [NO_PART; BATCH_PARTS];
        for frame in 0..frames {
            let (start, end) = spans[frame];
            parts[2 * frame] = &self.heads[start..end];
            parts[2 * frame + 1] = payloads[frame];
        }
        crate::proxy::write_all_parts::<BATCH_PARTS>(&mut *self.out, &parts[..2 * frames]).is_ok()
    }
}

struct Table {
    ids: mux::Ids,
    sinks: HashMap<u16, Sink>,
    full: bool,
    last_active: Instant,
}

struct Carrier {
    write: Mutex<Writer>,
    table: Mutex<Table>,
    cap: usize,
    lifetime: usize,
    idle: Duration,
    dead: std::sync::atomic::AtomicBool,
    close: Arc<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for Carrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Carrier")
            .field("cap", &self.cap)
            .field("dead", &self.dead())
            .finish_non_exhaustive()
    }
}

impl Carrier {
    fn new(uplink: Uplink, cap: usize, lifetime: usize, idle: Duration) -> Arc<Self> {
        let carrier = Arc::new(Carrier {
            write: Mutex::new(Writer {
                out: uplink.write,
                header: Vec::with_capacity(64),
                heads: Vec::with_capacity(BATCH * 8),
            }),
            table: Mutex::new(Table {
                ids: mux::Ids::new(0),
                sinks: HashMap::new(),
                full: false,
                last_active: Instant::now(),
            }),
            cap: cap.max(1),
            lifetime: lifetime.max(1),
            idle,
            dead: std::sync::atomic::AtomicBool::new(false),
            close: uplink.close,
        });
        let reader = Arc::clone(&carrier);
        std::thread::spawn(move || reader.demux(uplink.read));
        carrier
    }

    fn dead(&self) -> bool {
        self.dead.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn accepts(&self) -> bool {
        if self.dead() {
            return false;
        }
        let Ok(mut table) = self.table.lock() else {
            return false;
        };
        if table.full || table.ids.live() >= self.cap {
            return false;
        }
        table.last_active = Instant::now();
        true
    }

    fn frame(
        &self,
        id: u16,
        status: mux::Status,
        options: u8,
        target: Option<mux::Target<'_>>,
        global_id: Option<[u8; mux::GLOBAL_ID]>,
        data: &[u8],
    ) -> bool {
        if self.dead() {
            return false;
        }
        let Ok(mut writer) = self.write.lock() else {
            return false;
        };
        let written = writer.frame(id, status, options, target, global_id, data);
        drop(writer);
        if !written {
            self.retire();
        }
        written
    }

    /// The client's bulk path: one head per frame-sized chunk, one vectored write for the batch.
    fn keep(&self, id: u16, data: &[u8]) -> bool {
        if self.dead() {
            return false;
        }
        let Ok(mut writer) = self.write.lock() else {
            return false;
        };
        writer.keep(id, data)
    }

    /// The id is released only after its End frame is written, and `Ids` never reissues one.
    fn release(&self, id: u16) {
        let retire = {
            let Ok(mut table) = self.table.lock() else {
                return;
            };
            if table.sinks.remove(&id).is_none() {
                return;
            }
            table.ids.give_back();
            table.last_active = Instant::now();
            table.full && table.ids.live() == 0
        };
        if retire {
            self.retire();
        }
    }

    fn begin_idle_retire(&self) -> Option<bool> {
        let table = match self.table.lock() {
            Ok(table) => table,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self.dead() {
            return Some(false);
        }
        if !table.sinks.is_empty() || table.last_active.elapsed() < self.idle {
            return None;
        }
        Some(!self.dead.swap(true, std::sync::atomic::Ordering::Relaxed))
    }

    fn finish_retire(&self) {
        (self.close)();
        let mut table = match self.table.lock() {
            Ok(table) => table,
            Err(poisoned) => poisoned.into_inner(),
        };
        for (_, sink) in table.sinks.drain() {
            if let Sink::Tcp(sender, _) = sink {
                let _ = sender.try_send(Msg {
                    data: Vec::new(),
                    end: true,
                });
            }
        }
    }

    fn retire(&self) {
        if self.dead.swap(true, std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        self.finish_retire();
    }

    fn demux(self: Arc<Self>, mut read: Box<dyn Read + Send>) {
        let mut buf: Vec<u8> = Vec::with_capacity(crate::proxy::READ_SLICE);
        let mut buf_init = 0usize;
        let mut at = 0;
        loop {
            let mut progressed = false;
            loop {
                match mux::decode(&buf[at..], NewTail::Forward) {
                    Err(mux::Error::Short { .. }) => break,
                    Err(_) => {
                        self.retire();
                        return;
                    }
                    Ok((frame, used)) => {
                        at += used;
                        progressed = true;
                        self.dispatch(&frame);
                    }
                }
            }
            if progressed {
                if at >= buf.len() {
                    buf.clear();
                } else if at > 0 {
                    buf.drain(..at);
                }
                at = 0;
            }
            // SAFETY: `buf_init` describes `buf`, whose tail this loop owns.
            match unsafe { crate::proxy::read_into_tail(&mut read, &mut buf, &mut buf_init) } {
                Ok(0) => {
                    self.retire();
                    return;
                }
                Ok(_) => {}
                Err(error) if crate::proxy::is_timeout(&error) => {}
                Err(_) => {
                    self.retire();
                    return;
                }
            }
        }
    }

    fn dispatch(&self, frame: &mux::Incoming<'_>) {
        let sink = self
            .table
            .lock()
            .ok()
            .and_then(|table| table.sinks.get(&frame.id).cloned());
        let Some(sink) = sink else {
            return;
        };
        let target = frame.target.as_ref().and_then(sockaddr);
        match sink {
            Sink::Tcp(sender, closed) => {
                let data = frame.data.unwrap_or(&[]);
                let msg = Msg {
                    data: data.to_vec(),
                    end: frame.status == mux::Status::End,
                };
                if matches!(
                    sender.try_send(msg),
                    Err(TrySendError::Full(_) | TrySendError::Disconnected(_))
                ) {
                    closed.store(true, std::sync::atomic::Ordering::Relaxed);
                    self.frame(frame.id, mux::Status::End, 0, None, None, &[]);
                    self.release(frame.id);
                }
            }
            Sink::Udp(deliver, ended) => {
                if frame.status == mux::Status::End {
                    ended.store(true, std::sync::atomic::Ordering::Relaxed);
                    self.release(frame.id);
                    return;
                }
                if let Some(data) = frame.data {
                    deliver(data, target);
                }
            }
        }
    }
}

/// A frame target as the SOCKS reply header can name it; a name has no address to report.
fn sockaddr(target: &mux::Target<'_>) -> Option<SocketAddr> {
    match target.addr {
        ferrox_core::addr::Addr::V4(octets) => {
            Some(SocketAddr::from((Ipv4Addr::from(octets), target.port)))
        }
        ferrox_core::addr::Addr::V6(octets) => {
            Some(SocketAddr::from((Ipv6Addr::from(octets), target.port)))
        }
        ferrox_core::addr::Addr::Name(_) => None,
    }
}

pub(crate) struct Manager {
    open: Box<dyn Fn() -> Option<Uplink> + Send + Sync>,
    cap: usize,
    lifetime: usize,
    idle: Duration,
    carriers: Mutex<Vec<Arc<Carrier>>>,
    self_weak: OnceLock<Weak<Manager>>,
    monitor: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for Manager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Manager")
            .field("cap", &self.cap)
            .field("lifetime", &self.lifetime)
            .field("idle", &self.idle)
            .finish_non_exhaustive()
    }
}

impl Manager {
    pub(crate) fn new(
        cap: usize,
        open: impl Fn() -> Option<Uplink> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Self::with_lifetime(cap, LIFETIME, open)
    }

    pub(crate) fn with_lifetime(
        cap: usize,
        lifetime: usize,
        open: impl Fn() -> Option<Uplink> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Self::with_timing(cap, lifetime, IDLE, open)
    }

    #[cfg(all(test, unix))]
    pub(crate) fn with_idle(
        cap: usize,
        lifetime: usize,
        idle: Duration,
        open: impl Fn() -> Option<Uplink> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Self::with_timing(cap, lifetime, idle, open)
    }

    fn with_timing(
        cap: usize,
        lifetime: usize,
        idle: Duration,
        open: impl Fn() -> Option<Uplink> + Send + Sync + 'static,
    ) -> Arc<Self> {
        let manager = Arc::new(Manager {
            open: Box::new(open),
            cap: cap.max(1),
            lifetime: lifetime.max(1),
            idle: idle.max(Duration::from_millis(1)),
            carriers: Mutex::new(Vec::new()),
            self_weak: OnceLock::new(),
            monitor: std::sync::atomic::AtomicBool::new(false),
        });
        let _ = manager.self_weak.set(Arc::downgrade(&manager));
        manager
    }

    fn ensure_monitor(&self) {
        if self
            .monitor
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
        let Some(weak) = self.self_weak.get().cloned() else {
            self.monitor
                .store(false, std::sync::atomic::Ordering::Relaxed);
            return;
        };
        let idle = self.idle;
        std::thread::spawn(move || loop {
            std::thread::sleep(idle);
            let Some(manager) = weak.upgrade() else {
                return;
            };
            manager.retire_idle();
        });
    }

    fn retire_idle(&self) {
        let mut retiring = Vec::new();
        {
            let Ok(mut carriers) = self.carriers.lock() else {
                return;
            };
            carriers.retain(|carrier| match carrier.begin_idle_retire() {
                None => true,
                Some(started) => {
                    if started {
                        retiring.push(Arc::clone(carrier));
                    }
                    false
                }
            });
        }
        for carrier in retiring {
            carrier.finish_retire();
        }
    }

    fn pick(&self) -> Option<Arc<Carrier>> {
        let mut carriers = self.carriers.lock().ok()?;
        carriers.retain(|carrier| !carrier.dead());
        for carrier in carriers.iter() {
            if carrier.accepts() {
                return Some(Arc::clone(carrier));
            }
        }
        let uplink = (self.open)()?;
        let carrier = Carrier::new(uplink, self.cap, self.lifetime, self.idle);
        carriers.push(Arc::clone(&carrier));
        drop(carriers);
        self.ensure_monitor();
        Some(carrier)
    }

    fn reserve<T>(&self, mut make: impl FnMut(u16) -> (Sink, T)) -> Option<(Arc<Carrier>, u16, T)> {
        for _ in 0..PICKS {
            let carrier = self.pick()?;
            let mut table = carrier.table.lock().ok()?;
            if carrier.dead() || table.full || table.ids.live() >= carrier.cap {
                continue;
            }
            let Ok(id) = table.ids.take() else {
                continue;
            };
            if table.ids.opened() as usize >= carrier.lifetime {
                table.full = true;
            }
            table.last_active = Instant::now();
            let (sink, extra) = make(id);
            table.sinks.insert(id, sink);
            drop(table);
            return Some((carrier, id, extra));
        }
        None
    }

    /// One TCP session, on the first carrier with room or on a fresh one.
    pub(crate) fn dial(&self, target: &mux::Target<'_>) -> Option<Flow> {
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (carrier, id, replies) = self.reserve(|_| {
            let (send, replies) = sync_channel(REPLIES);
            (Sink::Tcp(send, Arc::clone(&closed)), replies)
        })?;
        if !carrier.frame(id, mux::Status::New, mux::DATA, Some(*target), None, &[]) {
            carrier.release(id);
            return None;
        }
        Some(Flow {
            carrier,
            id,
            replies: Some(replies),
            closed,
        })
    }

    /// One datagram session; its `New` frame carries the first payload and the deliver closure
    /// writes every reply back to the association.
    pub(crate) fn udp(
        &self,
        target: &mux::Target<'_>,
        global_id: Option<&[u8; mux::GLOBAL_ID]>,
        payload: &[u8],
        deliver: &Deliver,
    ) -> Option<UdpFlow> {
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (carrier, id, ()) =
            self.reserve(|_| (Sink::Udp(Arc::clone(deliver), Arc::clone(&ended)), ()))?;
        if !carrier.frame(
            id,
            mux::Status::New,
            mux::DATA,
            Some(*target),
            global_id.copied(),
            payload,
        ) {
            carrier.release(id);
            return None;
        }
        Some(UdpFlow { carrier, id, ended })
    }

    #[cfg(all(test, unix))]
    pub(crate) fn carrier_count(&self) -> usize {
        self.carriers.lock().map_or(0, |carriers| carriers.len())
    }

    /// The staging header's base and capacity, both unchanged by a push/drain cycle only if the
    /// frame encoder reuses its buffer instead of reallocating it.
    #[cfg(all(test, unix))]
    pub(crate) fn staged_identity(&self) -> (usize, usize) {
        self.carriers.lock().map_or((0, 0), |carriers| {
            carriers
                .iter()
                .map(|carrier| {
                    carrier.write.lock().map_or((0, 0), |writer| {
                        (writer.header.as_ptr() as usize, writer.header.capacity())
                    })
                })
                .max()
                .unwrap_or((0, 0))
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn target() -> mux::Target<'static> {
        mux::Target {
            network: mux::Network::Tcp,
            port: 80,
            addr: ferrox_core::addr::Addr::V4([127, 0, 0, 1]),
        }
    }

    fn datagram() -> mux::Target<'static> {
        mux::Target {
            network: mux::Network::Udp,
            port: 53,
            addr: ferrox_core::addr::Addr::V4([127, 0, 0, 1]),
        }
    }

    /// A manager whose carriers are loopback pairs the test keeps alive, so the demux never sees
    /// an end and the pool's own bookkeeping is what the assertions read.
    fn pooled(cap: usize, lifetime: usize) -> (Arc<Manager>, Arc<Mutex<Vec<UnixStream>>>) {
        pooled_with_idle(cap, lifetime, IDLE)
    }

    fn pooled_with_idle(
        cap: usize,
        lifetime: usize,
        idle: Duration,
    ) -> (Arc<Manager>, Arc<Mutex<Vec<UnixStream>>>) {
        let peers: Arc<Mutex<Vec<UnixStream>>> = Arc::new(Mutex::new(Vec::new()));
        let held = Arc::clone(&peers);
        let manager = Manager::with_idle(cap, lifetime, idle, move || {
            let (mine, peer) = UnixStream::pair().ok()?;
            let read = mine.try_clone().ok()?;
            // The peer only has to stay open and drain, so a full socket buffer never parks a writer.
            let mut sink = peer.try_clone().ok()?;
            std::thread::spawn(move || std::io::copy(&mut sink, &mut std::io::sink()));
            held.lock().ok()?.push(peer);
            Some(Uplink {
                read: Box::new(read),
                write: Box::new(mine),
                close: Arc::new(|| {}),
            })
        });
        (manager, peers)
    }

    #[test]
    fn a_pool_runs_a_hundred_and_twenty_eight_flows_on_one_carrier() {
        let (manager, peers) = pooled(128, LIFETIME);
        let mut flows = Vec::new();
        for _ in 0..128 {
            flows.push(manager.dial(&target()).expect("a flow"));
        }
        assert_eq!(manager.carrier_count(), 1, "128 sessions share the carrier");
        flows.push(manager.dial(&target()).expect("a flow past the cap"));
        assert_eq!(manager.carrier_count(), 2, "the cap dials a fresh carrier");
        assert!(peers.lock().is_ok_and(|peers| peers.len() == 2));
    }

    #[test]
    fn a_lifetime_retires_the_carrier_once_its_sessions_are_opened() {
        let (manager, _peers) = pooled(128, 3);
        for _ in 0..3 {
            manager.dial(&target()).expect("a flow");
        }
        assert_eq!(manager.carrier_count(), 1);
        manager.dial(&target()).expect("a flow past the lifetime");
        assert_eq!(
            manager.carrier_count(),
            2,
            "the retired carrier takes no more"
        );
    }

    #[test]
    fn an_idle_carrier_retires_after_one_window() {
        assert_eq!(IDLE, Duration::from_secs(16), "the reference's tick");
        let idle = Duration::from_millis(50);
        let (manager, _peers) = pooled_with_idle(4, LIFETIME, idle);
        let flow = manager.dial(&target()).expect("a flow");
        std::thread::sleep(idle * 3);
        assert_eq!(manager.carrier_count(), 1, "a live flow keeps its carrier");
        flow.close();
        let deadline = Instant::now() + Duration::from_secs(5);
        while manager.carrier_count() != 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(manager.carrier_count(), 0, "the idle carrier retired");
        let _fresh = manager.dial(&target()).expect("a fresh carrier");
        assert_eq!(manager.carrier_count(), 1, "the next flow dials anew");
    }

    #[test]
    fn a_peer_end_frees_a_datagram_session() {
        let peer = Arc::new(Mutex::new(None));
        let held = Arc::clone(&peer);
        let manager = Manager::with_lifetime(1, LIFETIME, move || {
            let (mine, other) = UnixStream::pair().ok()?;
            let read = mine.try_clone().ok()?;
            if let Ok(mut slot) = held.lock() {
                *slot = Some(other);
            }
            Some(Uplink {
                read: Box::new(read),
                write: Box::new(mine),
                close: Arc::new(|| {}),
            })
        });
        let deliver: Deliver = Arc::new(|_, _| {});
        let flow = manager
            .udp(&datagram(), None, b"first", &deliver)
            .expect("a session");
        let mut header = Vec::new();
        let end = mux::Outgoing {
            id: 1,
            status: mux::Status::End,
            options: 0,
            target: None,
            global_id: None,
        };
        let at = end.encode_header_into(&mut header);
        header.truncate(at);
        {
            let mut slot = peer.lock().expect("the peer");
            slot.as_mut()
                .expect("a peer")
                .write_all(&header)
                .expect("the end frame");
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while flow.send(&datagram(), b"later") && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            !flow.send(&datagram(), b"later"),
            "the ended flow refuses a send"
        );
        assert!(
            manager.udp(&datagram(), None, b"next", &deliver).is_some(),
            "the id came back"
        );
    }

    struct Recorder(Arc<Mutex<Vec<u8>>>);

    impl Write for Recorder {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("the recorded stream")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn frames(bytes: &[u8]) -> Vec<(u16, mux::Status)> {
        let mut at = 0;
        let mut out = Vec::new();
        while at < bytes.len() {
            let (frame, used) = mux::decode(&bytes[at..], NewTail::Forward).expect("a frame");
            out.push((frame.id, frame.status));
            at += used;
        }
        out
    }

    #[test]
    fn an_id_is_not_reused_before_its_end_is_written() {
        let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let peers: Arc<Mutex<Vec<UnixStream>>> = Arc::new(Mutex::new(Vec::new()));
        let held = Arc::clone(&peers);
        let manager = Manager::with_lifetime(4, LIFETIME, move || {
            let (mine, peer) = UnixStream::pair().ok()?;
            let read = mine.try_clone().ok()?;
            held.lock().ok()?.push(peer);
            Some(Uplink {
                read: Box::new(read),
                write: Box::new(Recorder(Arc::clone(&sink))),
                close: Arc::new(|| {}),
            })
        });
        let flow = manager.dial(&target()).expect("a flow");
        let id = flow.id;
        let carrier = Arc::clone(&flow.carrier);
        flow.close();
        let after_close = frames(&seen.lock().expect("the recorded stream"));
        assert_eq!(
            after_close.last(),
            Some(&(id, mux::Status::End)),
            "close returns after the End frame is on the wire"
        );
        assert!(carrier.frame(id, mux::Status::Keep, mux::DATA, None, None, b"reused"));
        assert_eq!(
            frames(&seen.lock().expect("the recorded stream")),
            vec![
                (id, mux::Status::New),
                (id, mux::Status::End),
                (id, mux::Status::Keep)
            ],
            "a frame for a reused id never crosses the old session's End"
        );
        assert_eq!(
            peers.lock().map_or(0, |peers| peers.len()),
            1,
            "the carrier's peer stays open so its demux does not retire"
        );
    }

    struct Calls(Arc<Mutex<(Vec<u8>, usize)>>);

    impl Write for Calls {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write_vectored(&[std::io::IoSlice::new(buf)])
        }

        fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
            let mut seen = self.0.lock().expect("the recorded stream");
            for buf in bufs {
                seen.0.extend_from_slice(buf);
            }
            seen.1 += 1;
            Ok(bufs.iter().map(|buf| buf.len()).sum())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The gate for `uplink-frames-per-write`: a 32 KiB send leaves as four frames under one call,
    /// and every payload byte reaches the wire.
    #[test]
    fn a_bulk_uplink_frames_four_keeps_in_one_write() {
        let seen: Arc<Mutex<(Vec<u8>, usize)>> = Arc::new(Mutex::new((Vec::new(), 0)));
        let sink = Arc::clone(&seen);
        let peers: Arc<Mutex<Vec<UnixStream>>> = Arc::new(Mutex::new(Vec::new()));
        let held = Arc::clone(&peers);
        let manager = Manager::with_lifetime(4, LIFETIME, move || {
            let (mine, peer) = UnixStream::pair().ok()?;
            let read = mine.try_clone().ok()?;
            held.lock().ok()?.push(peer);
            Some(Uplink {
                read: Box::new(read),
                write: Box::new(Calls(Arc::clone(&sink))),
                close: Arc::new(|| {}),
            })
        });
        let flow = manager.dial(&target()).expect("a flow");
        let payload: Vec<u8> = (0..4 * mux::CHUNK_MAX).map(|at| at as u8).collect();
        assert!(flow.send(&payload));
        let (bytes, calls) = {
            let seen = seen.lock().expect("the recorded stream");
            (seen.0.clone(), seen.1)
        };
        assert_eq!(
            calls, 2,
            "the New frame and the four-frame batch are one call each"
        );
        assert_eq!(
            frames(&bytes)
                .iter()
                .filter(|(_, status)| *status == mux::Status::Keep)
                .count(),
            4,
            "32 KiB leaves as four 8 KiB keeps",
        );
        let mut at = 0;
        let mut kept = Vec::new();
        while at < bytes.len() {
            let (frame, used) = mux::decode(&bytes[at..], NewTail::Forward).expect("a frame");
            kept.extend_from_slice(frame.data.unwrap_or(&[]));
            at += used;
        }
        assert_eq!(kept, payload, "every payload byte reaches the wire");
        assert_eq!(
            peers.lock().map_or(0, |peers| peers.len()),
            1,
            "the carrier's peer stays open so its demux does not retire"
        );
    }

    #[test]
    fn the_frame_header_holds_its_staging_across_a_push_drain_cycle() {
        let (manager, _peers) = pooled(128, LIFETIME);
        let flow = manager.dial(&target()).expect("a flow");
        assert!(flow.send(b"first"));
        let before = manager.staged_identity();
        assert_ne!(before.0, 0, "a carrier has encoded a frame");
        for _ in 0..2_000 {
            assert!(flow.send(b"payload"));
        }
        assert_eq!(manager.staged_identity(), before, "the header reallocated");
    }
}
