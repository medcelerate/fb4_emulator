//! Emulate a single FB4 laser controller toward QuickShow / BEYOND.
//!
//! Presents an FB4E on the network (ASDP announce), accepts the control connection, answers the
//! handshake (computing the device's `B = transform(A) ^ serial`) and the config sequence from
//! captured device-reply templates, decrypts incoming laser frames, and forwards the decoded
//! points (converted to Ether Dream points) into a shared buffer that the DAC driver consumes.
//!
//! NOTE: the device-side handshake/config replies are replayed from real FB4 captures. Getting
//! QuickShow/BEYOND to fully accept an emulated device may require iterating on per-session
//! fields (reply sequence counters, clock) against live software — see the crate README.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ether_dream::protocol::DacPoint;
use socket2::{Domain, Protocol, Socket, Type};

use crate::convert::to_dac_points;
use crate::etherdream::SharedPoints;

const CONTROL_PORT: u16 = 3348;
const ANNOUNCE_PORT: u16 = 9022;
/// ASDP discovery multicast group + port that QuickShow/BEYOND query to find FB4s.
const ASDP_GROUP: Ipv4Addr = Ipv4Addr::new(224, 76, 78, 75);
const ASDP_PORT: u16 = 20808;

/// One emulated FB4.
pub struct Fb4Emu {
    /// The local IP this fake FB4 presents on (each emulated device needs its own IP — see README).
    pub local_ip: Ipv4Addr,
    /// The serial this device advertises (unique per emulated FB4).
    pub serial: u32,
    /// Where decoded frames are published for the paired DAC driver.
    pub shared: SharedPoints,
    /// Flip Y when converting to Ether Dream coordinates.
    pub invert_y: bool,
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0)).collect()
}

/// Load the captured device-reply templates (flat `"key": "hex"` JSON, embedded).
fn load_templates() -> HashMap<String, Vec<u8>> {
    let s = include_str!("../assets/fb4_device_templates.json");
    let mut m = HashMap::new();
    for line in s.lines() {
        let line = line.trim().trim_end_matches(',');
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().trim_matches('"');
            let v = v.trim().trim_matches('"');
            if !v.is_empty() && v.len() % 2 == 0 && v.bytes().all(|b| b.is_ascii_hexdigit()) {
                m.insert(k.to_string(), hex_decode(v));
            }
        }
    }
    m
}

fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Run this emulated FB4 forever: announce, and accept/serve control connections.
pub fn run(emu: Arc<Fb4Emu>) {
    let templates = Arc::new(load_templates());

    // ASDP presence announce loop.
    {
        let emu = emu.clone();
        let templates = templates.clone();
        std::thread::spawn(move || discovery_responder(&emu, &templates));
    }

    // UDP turbo (0xe04 / 0dbe) frame listener.
    {
        let emu = emu.clone();
        std::thread::spawn(move || udp_turbo_loop(&emu));
    }

    // TCP control server. A freshly-added IP alias isn't immediately bindable — Windows runs
    // Duplicate Address Detection for a moment (error 10049) — so retry for a short while.
    let bind = SocketAddrV4::new(emu.local_ip, CONTROL_PORT);
    let bind_deadline = Instant::now() + Duration::from_secs(20);
    let listener = loop {
        match TcpListener::bind(bind) {
            Ok(l) => break l,
            Err(e) if Instant::now() < bind_deadline => {
                eprintln!("[fb4 {} serial={}] waiting for {} to become bindable ({e})", emu.local_ip, emu.serial, bind);
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(e) => {
                eprintln!("[fb4 {} serial={}] cannot bind {}: {e}", emu.local_ip, emu.serial, bind);
                eprintln!("  Is {} assigned to a NIC? Use an existing NIC IP, or add the alias as Administrator.", emu.local_ip);
                return;
            }
        }
    };
    println!("[fb4 {} serial={}] emulating FB4E, listening on :{CONTROL_PORT}", emu.local_ip, emu.serial);
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let emu = emu.clone();
                let templates = templates.clone();
                std::thread::spawn(move || {
                    if let Err(e) = serve(stream, &emu, &templates) {
                        eprintln!("[fb4 {} serial={}] session ended: {e}", emu.local_ip, emu.serial);
                    }
                });
            }
            Err(e) => eprintln!("[fb4 {}] accept error: {e}", emu.local_ip),
        }
    }
}

/// Bind a reusable UDP socket (SO_REUSEADDR, +SO_REUSEPORT on unix) with a short read timeout.
fn reuse_udp(bind: SocketAddrV4, broadcast: bool) -> io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    if broadcast {
        s.set_broadcast(true)?;
    }
    s.bind(&SocketAddr::V4(bind).into())?;
    let u: UdpSocket = s.into();
    u.set_read_timeout(Some(Duration::from_millis(300)))?;
    Ok(u)
}

/// Bind a UDP socket joined to the ASDP multicast group so we receive QuickShow/BEYOND's queries.
fn asdp_multicast_socket(iface: Ipv4Addr) -> io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, ASDP_PORT)).into())?;
    s.join_multicast_v4(&ASDP_GROUP, &iface)?;
    let u: UdpSocket = s.into();
    u.set_read_timeout(Some(Duration::from_millis(300)))?;
    Ok(u)
}

/// Make QuickShow/BEYOND discover us.
///
/// A real FB4 is found by *replying* to the host's discovery, unicast, from its own `:9022` — the
/// host then locates the device by that reply's source address. So we: listen on `:9022` and on
/// the ASDP multicast group (`224.76.78.75:20808`), and whenever a host probes, unicast the `0080`
/// announce back to it from our `:9022`. We also emit an unsolicited broadcast every second.
///
/// IMPORTANT: run this on a DIFFERENT host than QuickShow/BEYOND. A real FB4 is a separate network
/// device; on the same machine it shares the host's IP and `:9022`, so the host can't treat it as a
/// remote device. Give the emulator its own machine (or VM) with its own IP on the laser subnet.
fn discovery_responder(emu: &Fb4Emu, templates: &HashMap<String, Vec<u8>>) {
    let mut ann = match templates.get("announce") {
        Some(a) => a.clone(),
        None => return,
    };
    if ann.len() > 0x28 {
        put_u32(&mut ann, 0x24, emu.serial); // serial @ 0x24 in the announcement
    }

    // Socket on our IP:9022 — receives host probes on 9022 and sends replies *from* :9022.
    let disc = match reuse_udp(SocketAddrV4::new(emu.local_ip, ANNOUNCE_PORT), true) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[fb4 {}] cannot bind :{ANNOUNCE_PORT} for discovery: {e}", emu.local_ip);
            return;
        }
    };
    // Join the ASDP multicast group (best effort) to hear the host's discovery queries.
    let mcast = asdp_multicast_socket(emu.local_ip).ok();
    if mcast.is_none() {
        eprintln!("[fb4 {}] warning: could not join ASDP multicast {ASDP_GROUP}:{ASDP_PORT}", emu.local_ip);
    }

    let o = emu.local_ip.octets();
    let bcast_targets = [
        SocketAddrV4::new(Ipv4Addr::BROADCAST, ANNOUNCE_PORT),
        SocketAddrV4::new(Ipv4Addr::new(o[0], o[1], 255, 255), ANNOUNCE_PORT),
    ];
    let mut last_bcast = Instant::now() - Duration::from_secs(5);
    let mut buf = [0u8; 2048];

    loop {
        // Unsolicited announce broadcast every second.
        if last_bcast.elapsed() >= Duration::from_secs(1) {
            for t in &bcast_targets {
                let _ = disc.send_to(&ann, t);
            }
            last_bcast = Instant::now();
        }

        // Reply unicast to any host that probes us (on 9022 or via the ASDP multicast query).
        let mut host: Option<Ipv4Addr> = None;
        if let Ok((_, SocketAddr::V4(src))) = disc.recv_from(&mut buf) {
            if *src.ip() != emu.local_ip {
                host = Some(*src.ip());
            }
        }
        if host.is_none() {
            if let Some(m) = &mcast {
                if let Ok((_, SocketAddr::V4(src))) = m.recv_from(&mut buf) {
                    if *src.ip() != emu.local_ip {
                        host = Some(*src.ip());
                    }
                }
            }
        }
        if let Some(h) = host {
            let _ = disc.send_to(&ann, SocketAddrV4::new(h, ANNOUNCE_PORT));
        }
    }
}

/// Serve one control connection: handshake, config, then decrypt frames + emit scan acks.
fn serve(mut stream: TcpStream, emu: &Fb4Emu, templates: &HashMap<String, Vec<u8>>) -> std::io::Result<()> {
    stream.set_nodelay(true).ok();
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 65536];

    let mut keybase: Option<u64> = None;
    let mut scanning = false;
    let mut last_ack = Instant::now();

    loop {
        // Emit periodic scan-out acks so the host believes we're scanning.
        if scanning && last_ack.elapsed() >= Duration::from_millis(500) {
            if let Some(d) = templates.get("0d8a") {
                let _ = stream.write_all(d);
            }
            last_ack = Instant::now();
        }
        stream.set_read_timeout(Some(Duration::from_millis(200))).ok();
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(()), // peer closed
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                continue
            }
            Err(e) => return Err(e),
        }

        // Extract and handle complete 40fb messages.
        let mut i = 0;
        while i + 12 <= buf.len() {
            if &buf[i..i + 2] != b"\x40\xfb" {
                i += 1;
                continue;
            }
            let size = u32::from_le_bytes([buf[i + 8], buf[i + 9], buf[i + 10], buf[i + 11]]) as usize;
            if size < 12 || i + size > buf.len() {
                break; // incomplete — wait for more
            }
            let msg = &buf[i..i + size];
            handle_msg(msg, &mut stream, emu, templates, &mut keybase, &mut scanning)?;
            i += size;
        }
        buf.drain(..i);
    }
}

fn handle_msg(
    msg: &[u8],
    stream: &mut TcpStream,
    emu: &Fb4Emu,
    templates: &HashMap<String, Vec<u8>>,
    keybase: &mut Option<u64>,
    scanning: &mut bool,
) -> std::io::Result<()> {
    let (fmt, sub) = (msg[4], msg[5]);
    match (fmt, sub) {
        (0x01, 0x01) => {
            // Handshake 0101: read nonce A @ 0x2C, compute B and the session keybase, reply 0181.
            if msg.len() >= 0x30 {
                let a = u32::from_le_bytes([msg[0x2C], msg[0x2D], msg[0x2E], msg[0x2F]]);
                let b = fb4::codec::transform_nonce(a) ^ emu.serial;
                *keybase = Some(fb4::codec::session_keybase(a, b));
                if let Some(t) = templates.get("0181") {
                    let mut reply = t.clone();
                    if reply.len() >= 0x54 {
                        put_u32(&mut reply, 0x34, emu.serial); // serial
                        put_u32(&mut reply, 0x50, b); // B (challenge-response)
                    }
                    stream.write_all(&reply)?;
                }
            }
        }
        (0x02, 0x0e) => {
            // TCP laser frame (0xe02): decrypt, parse, forward.
            if let Some(kb) = *keybase {
                decode_tcp_frame(msg, kb, emu);
                *scanning = true;
            }
        }
        (0x00, _) if msg.len() == 32 => {
            // Clock-sync frame (0x00): reply with the 0080 clock report.
            if let Some(t) = templates.get("0080") {
                stream.write_all(t)?;
            }
        }
        (0x02, 0x00) => {
            *scanning = true; // 0200 = enable output
            if let Some(t) = templates.get("0b8a") {
                stream.write_all(t)?;
            }
        }
        (0x01, 0x00) => *scanning = false, // 0100 = disable output
        _ => {
            // Config command: reply with the matching device template if we have one.
            let key = format!("{:02x}8a", fmt);
            let alt = format!("{:02x}80", fmt);
            let alt2 = format!("{:02x}8d", fmt);
            if let Some(t) = templates.get(&key).or_else(|| templates.get(&alt)).or_else(|| templates.get(&alt2)) {
                stream.write_all(t)?;
            }
        }
    }
    Ok(())
}

/// Decrypt a TCP `0xe02` frame body and forward its decoded points to the shared buffer.
fn decode_tcp_frame(msg: &[u8], keybase: u64, emu: &Fb4Emu) {
    let seq = u32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]);
    let ts_a = u32::from_le_bytes([msg[16], msg[17], msg[18], msg[19]]);
    let se_a = u32::from_le_bytes([msg[20], msg[21], msg[22], msg[23]]);
    let key = fb4::codec::tcp_frame_key(keybase, ts_a, se_a, seq);
    let plain = fb4::codec::des_cbc_decrypt(key, &msg[32..]);
    let (_rate, points) = fb4::codec::parse_point_stream(&plain);
    if !points.is_empty() {
        let dac: Vec<DacPoint> = to_dac_points(&points, emu.invert_y);
        *emu.shared.lock().unwrap() = dac;
    }
}

/// Receive UDP turbo (`0dbe`) fragments, reassemble, decrypt (`0xe04`), and forward points.
fn udp_turbo_loop(emu: &Fb4Emu) {
    let sock = match UdpSocket::bind(SocketAddrV4::new(emu.local_ip, CONTROL_PORT)) {
        Ok(s) => s,
        Err(_) => return, // TCP server may also want this IP:port for UDP — best effort
    };
    let mut frags: HashMap<u16, Vec<(u16, Vec<u8>)>> = HashMap::new();
    let mut b = [0u8; 2048];
    loop {
        let n = match sock.recv(&mut b) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let pl = &b[..n];
        if pl.len() < 16 || &pl[0..2] != b"\x0d\xbe" {
            continue;
        }
        let counter = u16::from_le_bytes([pl[12], pl[13]]);
        let off = u16::from_le_bytes([pl[10], pl[11]]);
        let last = pl[6] == 0x01;
        frags.entry(counter).or_default().push((off, pl[16..].to_vec()));
        if last {
            if let Some(parts) = frags.remove(&counter) {
                let mut ordered = parts;
                ordered.sort_by_key(|(o, _)| *o);
                let body: Vec<u8> = ordered.into_iter().flat_map(|(_, d)| d).collect();
                if body.len() >= 32 && body[4] == 0x04 {
                    let seq = u32::from_le_bytes([body[12], body[13], body[14], body[15]]);
                    let ts_a = u32::from_le_bytes([body[16], body[17], body[18], body[19]]);
                    let se_a = u32::from_le_bytes([body[20], body[21], body[22], body[23]]);
                    let key = fb4::codec::turbo_key(seq, ts_a, se_a, counter as u32);
                    let plain = fb4::codec::des_cbc_decrypt(key, &body[32..]);
                    let (_rate, points) = fb4::codec::parse_point_stream(&plain);
                    if !points.is_empty() {
                        *emu.shared.lock().unwrap() = to_dac_points(&points, emu.invert_y);
                    }
                }
            }
        }
        if frags.len() > 64 {
            frags.clear(); // guard against unbounded growth from dropped fragments
        }
    }
}
