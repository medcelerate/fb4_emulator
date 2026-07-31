//! Per-device session: announce, connect, handshake, configure, and stream — with
//! automatic reconnection. One `run_session` task owns one FB4 for the manager's lifetime.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::sync::{watch, Notify};
use tokio::time::Instant;

use crate::clock::ClockBase;
use crate::messages as msg;
use crate::proto::{self, Point};

/// A ready-to-stream frame: pre-serialized point-stream body + its parameters.
#[derive(Clone)]
pub struct FrameData {
    pub pps: u32,
    pub count: usize, // points including alignment padding (the header count field)
    pub body: Vec<u8>,
}

impl FrameData {
    pub fn from_points(points: &[Point], pps: u32) -> Self {
        let body = proto::serialize_points(points, pps);
        let count = u16::from_le_bytes([body[2], body[3]]) as usize;
        FrameData { pps, count, body }
    }

    /// A single blanked point — streamed until the app sets real content, keeping the FB4 armed.
    pub fn blank(pps: u32) -> Self {
        Self::from_points(&[Point::default(), Point::default()], pps)
    }
}

/// Per-device configuration.
#[derive(Clone)]
pub struct DeviceConfig {
    pub local: Option<Ipv4Addr>,
    pub device_id: [u8; 5],
    pub lead: f64,
    pub transport: crate::Transport,
}

/// Run one device forever: (re)connect, handshake, configure, and stream. The presence/announce
/// broadcast is handled once for the whole segment by [`crate::discovery::run_net`].
pub async fn run_session(ip: Ipv4Addr, cfg: DeviceConfig, frame_rx: watch::Receiver<Arc<FrameData>>) {
    let clock = ClockBase::new();
    // Let the shared announce register the host before the first connect.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    loop {
        let _ = session_once(ip, &cfg, &clock, &frame_rx).await;
        // Connection failed or dropped — reset the clock base and back off before retrying.
        clock.unset();
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn connect(ip: Ipv4Addr, local: Option<Ipv4Addr>) -> std::io::Result<tokio::net::TcpStream> {
    let sock = TcpSocket::new_v4()?;
    if let Some(l) = local {
        sock.bind(SocketAddrV4::new(l, 0).into())?;
    }
    let fut = sock.connect(SocketAddrV4::new(ip, proto::CONTROL_PORT).into());
    tokio::time::timeout(Duration::from_secs(3), fut).await?
}

/// One connect→handshake→config→stream cycle. Returns Err on any failure (triggers reconnect).
async fn session_once(
    ip: Ipv4Addr,
    cfg: &DeviceConfig,
    clock: &ClockBase,
    frame_rx: &watch::Receiver<Arc<FrameData>>,
) -> std::io::Result<()> {
    let mut stream = connect(ip, cfg.local).await?;
    let mut seq: u32 = 0;

    // ── Handshake ────────────────────────────────────────────────────────────
    seq += 1;
    let (hs, a) = msg::build_handshake(seq);
    stream.write_all(&hs).await?;

    let mut buf = vec![0u8; 65536];
    let n = tokio::time::timeout(Duration::from_millis(1200), stream.read(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no 0181 reply"))??;
    let reply = msg::parse_handshake_reply(&buf[..n])
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "0181 parse failed"))?;

    // The device derives B = transform(A) ^ serial as a handshake check. We don't hard-gate on
    // it (the frame keybase is derived independently), but this validates our parse of the reply.
    let _handshake_ok = proto::transform_nonce(a) ^ reply.serial == reply.b;
    let _model = reply.model;

    let keybase = proto::session_keybase(a, reply.b);
    if reply.clock_acc != 0 {
        clock.set_base(reply.clock_acc);
    }

    // ── Configuration ────────────────────────────────────────────────────────
    for m in [
        msg::cfg_070a(next(&mut seq)),
        msg::cfg_080a(next(&mut seq)),
        msg::cfg_3100(next(&mut seq)),
        msg::cfg_030a(next(&mut seq)),
        msg::cfg_040a(next(&mut seq)),
    ] {
        send_drain(&mut stream, &m).await?;
    }

    // Set device date/time.
    let (y, mo, d, h, mi, s) = wall_datetime();
    send_drain(&mut stream, &msg::set_clock(next(&mut seq), 0x05, y, mo, d)).await?;
    send_drain(&mut stream, &msg::set_clock(next(&mut seq), 0x06, h, mi, s)).await?;

    // Identity stamp.
    let td = proto::tdatetime(y as i32, mo, d, h, mi, s, 0);
    send_drain(&mut stream, &msg::build_0f0a(next(&mut seq), &cfg.device_id, td)).await?;

    // Per-channel setup, then enable output.
    for ch in 0..8u8 {
        send_drain(&mut stream, &msg::cfg_010d(next(&mut seq), ch)).await?;
    }
    stream.write_all(&msg::enable_output(next(&mut seq))).await?;

    // ── Stream ───────────────────────────────────────────────────────────────
    stream_frames(stream, keybase, seq, cfg.lead, cfg.transport, ip, cfg.local, clock, frame_rx.clone()).await
}

/// Open a UDP socket for turbo streaming: bound to an ephemeral local port (the announce holds
/// `:9022`) and connected to the FB4's control port.
async fn open_udp(ip: Ipv4Addr, local: Option<Ipv4Addr>) -> std::io::Result<tokio::net::UdpSocket> {
    let bind = SocketAddr::from(SocketAddrV4::new(local.unwrap_or(Ipv4Addr::UNSPECIFIED), 0));
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(SocketAddr::from(SocketAddrV4::new(ip, proto::CONTROL_PORT))).await?;
    Ok(sock)
}

/// The streaming loop: send the current frame continuously with the correct timeline and
/// cadence, interleaving a ~1 Hz keep-alive. In `UdpTurbo` mode the point frames go out as
/// `0dbe`-fragmented `0xe04` datagrams over UDP while the TCP control connection carries only the
/// keep-alive. Returns when the TCP connection drops.
#[allow(clippy::too_many_arguments)]
async fn stream_frames(
    stream: tokio::net::TcpStream,
    keybase: u64,
    mut seq: u32,
    lead: f64,
    transport: crate::Transport,
    ip: Ipv4Addr,
    local: Option<Ipv4Addr>,
    clock: &ClockBase,
    frame_rx: watch::Receiver<Arc<FrameData>>,
) -> std::io::Result<()> {
    let (mut rd, mut wr) = stream.into_split();

    // Reader task: drain device replies; signal death on EOF/error so the writer can reconnect.
    let death = Arc::new(Notify::new());
    let death2 = death.clone();
    let reader = tokio::spawn(async move {
        let mut b = [0u8; 8192];
        loop {
            match rd.read(&mut b).await {
                Ok(0) | Err(_) => {
                    death2.notify_waiters();
                    return;
                }
                Ok(_) => {}
            }
        }
    });

    // Turbo mode streams frames over a separate UDP socket.
    let udp = match transport {
        crate::Transport::UdpTurbo => Some(open_udp(ip, local).await?),
        crate::Transport::Tcp => None,
    };

    let lead_acc = proto::secs_to_acc(lead);
    let mut timing_acc: u64 = 0;
    let mut seeded = false;
    let mut framenum: u32 = 0;
    let mut next = Instant::now();
    let mut last_keepalive = Instant::now();

    let result = loop {
        // Wait for the next send slot, or bail if the TCP connection died.
        tokio::select! {
            _ = death.notified() => break Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "disconnected")),
            _ = tokio::time::sleep_until(next) => {}
        }

        let fd: Arc<FrameData> = frame_rx.borrow().clone();
        if !seeded {
            timing_acc = clock.now().wrapping_add(lead_acc);
            seeded = true;
        }

        seq += 1;
        let span = proto::frame_span_acc(fd.count, fd.pps);
        match &udp {
            Some(sock) => {
                framenum += 1;
                let frags = proto::build_udp_turbo_frames(seq, framenum, timing_acc, span, &fd.body);
                let mut failed = false;
                for frag in &frags {
                    if sock.send(frag).await.is_err() {
                        failed = true;
                        break;
                    }
                }
                if failed {
                    break Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "udp send failed"));
                }
            }
            None => {
                let frame = proto::build_tcp_frame(keybase, seq, timing_acc, span, &fd.body);
                if wr.write_all(&frame).await.is_err() {
                    break Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "write failed"));
                }
            }
        }
        timing_acc = timing_acc.wrapping_add(span + proto::INTER_FRAME_GAP);

        // Keep-alive on the TCP control connection (both modes).
        if last_keepalive.elapsed() >= Duration::from_secs(1) {
            seq += 1;
            if wr.write_all(&msg::keepalive(seq)).await.is_err() {
                break Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "keepalive failed"));
            }
            last_keepalive = Instant::now();
        }

        // Cadence must match the timeline advance: one frame per (count/rate + 0.5 ms).
        let interval = Duration::from_secs_f64(fd.count as f64 / fd.pps as f64)
            + Duration::from_micros(500);
        next += interval;
    };

    // Best-effort: disable output on a clean-ish teardown.
    seq += 1;
    let _ = wr.write_all(&msg::disable_output(seq)).await;
    reader.abort();
    result
}

fn next(seq: &mut u32) -> u32 {
    *seq += 1;
    *seq
}

async fn send_drain(stream: &mut tokio::net::TcpStream, m: &[u8]) -> std::io::Result<()> {
    stream.write_all(m).await?;
    // Best-effort short drain of any reply; ignore timeouts/content.
    let mut b = [0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_millis(60), stream.read(&mut b)).await;
    Ok(())
}

/// Local wall date/time as (year, month, day, hour, minute, second). Uses a minimal
/// civil-time conversion so the crate needs no date/time dependency.
fn wall_datetime() -> (u32, u32, u32, u32, u32, u32) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400);
    let (h, mi, s) = ((tod / 3600) as u32, ((tod % 3600) / 60) as u32, (tod % 60) as u32);
    let (y, mo, d) = civil_from_days(days);
    (y, mo, d, h, mi, s)
}

/// Inverse of days-from-civil (Howard Hinnant), for the Unix epoch.
fn civil_from_days(z: i64) -> (u32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}
