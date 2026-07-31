//! ASDP discovery and the presence/announce loop.
//!
//! The FB4 must see periodic broadcast "announce" datagrams (from UDP source port 9022)
//! to register a host and sync its scan clock. Discovery broadcasts the same announce
//! plus an ASDP query and collects FB4 replies on :9022.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::messages::hex_decode;

const ASDP_DISCOVERY: &str = "5f617364705f760101050000623273782c467875746d6c6e00000018000000000007a120000000000000033a00000000000000007365737300000008623273782c467875737473740000001100000000000000000000000000000000006d65703400000006a9fec393ccf6";
const ASDP_DISCOVERY_SHORT: &str = "5f617364705f760103000000623273782c467875";
const ASDP_ANNOUNCE: &str = "0dbe0000000092271803000004000000b29def370b000000010000000000000001000400020000004c0041005300450052005a0045004e003100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005000500000092070000000000000000000000000000000000000000000000002c7c0800000000000000000000000000b08008000000000000000000000000000feb0500000000000000000000000000e70e08000000000000000000000000000000000000000000000000000000000000";

const ANNOUNCE_LEN: usize = 792;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub ip: Ipv4Addr,
    pub serial: u32,
}

/// Build one announce datagram carrying the timeline clock and an activate flag.
/// `activate` sets byte[4]=0x01 (the wake signal) vs 0x00 (presence only).
pub fn build_announce(clock_acc: u64, counter: u32, activate: bool) -> Vec<u8> {
    let mut a = hex_decode(ASDP_ANNOUNCE);
    if a.len() < ANNOUNCE_LEN {
        a.resize(ANNOUNCE_LEN, 0);
    }
    a[4] = if activate { 0x01 } else { 0x00 };
    a[5] = 0x00;
    let ts = ((clock_acc & 0xFFFF_FFFF) as u32) / 2;
    let se = (clock_acc >> 32) as u32;
    a[0x0C..0x10].copy_from_slice(&counter.to_le_bytes());
    a[0x10..0x14].copy_from_slice(&ts.to_le_bytes());
    a[0x14..0x18].copy_from_slice(&se.to_le_bytes());
    a
}

/// Subnet broadcast address for a local link-local/private IP (e.g. 169.254.x.x -> 169.254.255.255).
fn subnet_broadcast(local: Option<Ipv4Addr>) -> Ipv4Addr {
    match local {
        Some(ip) => {
            let o = ip.octets();
            Ipv4Addr::new(o[0], o[1], 255, 255)
        }
        None => Ipv4Addr::new(255, 255, 255, 255),
    }
}

/// Open a broadcast-enabled UDP socket bound to (local):9022, reusing the address so the
/// announce loop and the reply listener share it. Returns an error if the port is held
/// (e.g. by BEYOND/QuickShow) and no fallback is possible.
pub fn open_announce_socket(local: Option<Ipv4Addr>) -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    let bind_ip = local.unwrap_or(Ipv4Addr::UNSPECIFIED);
    let bind_addr = SocketAddr::from(SocketAddrV4::new(bind_ip, crate::proto::ANNOUNCE_PORT));
    sock.bind(&bind_addr.into())?;
    if let Some(ip) = local {
        // Steer multicast egress onto the FB4's interface.
        let _ = sock.set_multicast_if_v4(&ip);
        let _ = sock.set_multicast_ttl_v4(1);
    }
    sock.set_nonblocking(true)?;
    UdpSocket::from_std(sock.into())
}

fn discovery_targets(local: Option<Ipv4Addr>) -> (SocketAddr, SocketAddr) {
    let mcast: Ipv4Addr = crate::proto::DISCOVERY_MCAST.parse().unwrap();
    let mcast = SocketAddr::new(IpAddr::V4(mcast), crate::proto::DISCOVERY_PORT);
    let bcast = SocketAddr::new(IpAddr::V4(subnet_broadcast(local)), crate::proto::DISCOVERY_PORT);
    (mcast, bcast)
}

fn announce_targets(local: Option<Ipv4Addr>) -> [SocketAddr; 2] {
    [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), crate::proto::ANNOUNCE_PORT),
        SocketAddr::new(IpAddr::V4(subnet_broadcast(local)), crate::proto::ANNOUNCE_PORT),
    ]
}

/// One-shot discovery: broadcast the query + announce for `duration` and collect FB4 replies.
/// (Utility; the manager uses the continuous [`run_net`] instead.)
#[allow(dead_code)]
pub async fn discover(local: Option<Ipv4Addr>, duration: Duration) -> std::io::Result<Vec<DiscoveredDevice>> {
    let sock = open_announce_socket(local)?;
    let disc = hex_decode(ASDP_DISCOVERY);
    let disc_short = hex_decode(ASDP_DISCOVERY_SHORT);
    let (mcast, bcast) = discovery_targets(local);
    let ann_tgts = announce_targets(local);

    let deadline = tokio::time::Instant::now() + duration;
    let mut counter: u32 = 4;
    let mut found: Vec<DiscoveredDevice> = Vec::new();
    let mut buf = [0u8; 2048];
    let mut tick = tokio::time::interval(Duration::from_millis(300));
    let start = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            _ = tick.tick() => {
                let _ = sock.send_to(&disc, mcast).await;
                let _ = sock.send_to(&disc, bcast).await;
                let _ = sock.send_to(&disc_short, mcast).await;
                let elapsed = start.elapsed().as_secs_f64();
                let acc = crate::proto::secs_to_acc(elapsed);
                for activate in [false, true] {
                    let a = build_announce(acc, counter, activate);
                    for t in &ann_tgts { let _ = sock.send_to(&a, *t).await; }
                    counter += 1;
                }
            }
            r = sock.recv_from(&mut buf) => {
                if let Ok((n, src)) = r {
                    if let std::net::SocketAddr::V4(sa) = src {
                        if let Some(dev) = parse_reply(&buf[..n], *sa.ip()) {
                            if !found.iter().any(|d| d.ip == dev.ip) {
                                found.push(dev);
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(found)
}

/// The shared network task: on a single `:9022` socket, continuously broadcast discovery +
/// presence announces (so FB4s stay registered) and listen for replies, forwarding each
/// discovered device on `found_tx`. One instance serves every FB4 on the segment.
///
/// `activate` (the wake bit) is asserted only in a short opening burst plus a rare re-assert —
/// hammering it resets the scanner. The announce clock uses an elapsed-time base; per-device
/// frame timing is stamped separately in each device's own clock domain (see `session.rs`).
pub async fn run_net(
    local: Option<Ipv4Addr>,
    found_tx: tokio::sync::mpsc::UnboundedSender<DiscoveredDevice>,
) {
    let sock = match open_announce_socket(local) {
        Ok(s) => s,
        Err(_) => return, // :9022 held (BEYOND/QuickShow open) — cannot announce/discover
    };
    let disc = hex_decode(ASDP_DISCOVERY);
    let disc_short = hex_decode(ASDP_DISCOVERY_SHORT);
    let (mcast, bcast) = discovery_targets(local);
    let ann_tgts = announce_targets(local);
    let start = tokio::time::Instant::now();

    let mut counter: u32 = 4;
    let mut ann_num: u32 = 0;
    let mut buf = [0u8; 2048];
    let mut tick = tokio::time::interval(Duration::from_millis(400));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let _ = sock.send_to(&disc, mcast).await;
                let _ = sock.send_to(&disc, bcast).await;
                if ann_num % 4 == 0 {
                    let _ = sock.send_to(&disc_short, mcast).await;
                }
                let acc = crate::proto::secs_to_acc(start.elapsed().as_secs_f64());
                let activate = if ann_num < 6 { ann_num % 2 == 1 } else { ann_num % 13 == 0 };
                let a = build_announce(acc, counter, activate);
                for t in &ann_tgts {
                    let _ = sock.send_to(&a, *t).await;
                }
                counter += 1;
                ann_num += 1;
            }
            r = sock.recv_from(&mut buf) => {
                if let Ok((n, SocketAddr::V4(sa))) = r {
                    if let Some(dev) = parse_reply(&buf[..n], *sa.ip()) {
                        let _ = found_tx.send(dev);
                    }
                }
            }
        }
    }
}

/// Parse an FB4 discovery reply: `40fb .. .. 80 ..` with model "FB4E" at 0x20, serial at 0x24.
fn parse_reply(buf: &[u8], src: Ipv4Addr) -> Option<DiscoveredDevice> {
    if buf.len() >= 0x28 && buf[0] == 0x40 && buf[1] == 0xFB && buf[5] == 0x80 && &buf[0x20..0x24] == b"FB4E" {
        let serial = u32::from_le_bytes([buf[0x24], buf[0x25], buf[0x26], buf[0x27]]);
        Some(DiscoveredDevice { ip: src, serial })
    } else {
        None
    }
}
