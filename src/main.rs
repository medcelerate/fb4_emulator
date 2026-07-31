//! fb4_bridge — present Ether Dream DACs to QuickShow/BEYOND as FB4s.
//!
//! Discovers Ether Dream DACs on the network and, for each, emulates an FB4E: QuickShow/BEYOND
//! discovers and connects to the emulated FB4, and the laser stream it sends is decrypted,
//! decoded, converted, and forwarded to the paired Ether Dream DAC.
//!
//! Usage:
//!   fb4_bridge <fb4-ip-1> [fb4-ip-2 ...]
//!
//! Each `fb4-ip` is a local IP this host owns (add IP aliases to your NIC for more than one) —
//! one emulated FB4 is presented per DAC found, bound to these IPs in order. See README.

mod convert;
mod etherdream;
mod fb4_device;

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ether_dream::dac::MacAddress;
use ether_dream::protocol::{DacBroadcast, ReadFromBytes};
use socket2::{Domain, Protocol, Socket, Type};

use etherdream::SharedPoints;
use fb4_device::Fb4Emu;

const DISCOVERY_SECS: u64 = 6;
/// Ether Dream DACs broadcast a 36-byte status datagram to this UDP port ~once per second.
const ETHERDREAM_BROADCAST_PORT: u16 = 7654;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let add_aliases = args.iter().any(|a| a == "--add-aliases");
    let iface = arg_value(&args, "--iface");
    let given: Vec<Ipv4Addr> = args.iter().filter_map(|s| s.parse().ok()).collect();

    if given.is_empty() {
        eprintln!("usage: fb4_bridge <base-ip> [--iface NAME] [--add-aliases]");
        eprintln!("       fb4_bridge <fb4-ip-1> <fb4-ip-2> ...   (explicit list)");
        eprintln!();
        eprintln!("  With ONE base IP, one FB4 IP is auto-assigned per DAC by incrementing the base");
        eprintln!("  (e.g. 169.254.100.10, .11, .12 ...). Each IP must exist on your NIC — pass");
        eprintln!("  --add-aliases (with --iface) to add them for you (needs admin/root), or add");
        eprintln!("  them yourself; the commands are printed below.");
        std::process::exit(1);
    }

    print_interfaces();
    println!("Discovering Ether Dream DACs for {DISCOVERY_SECS}s...");
    let dacs = discover_dacs(Duration::from_secs(DISCOVERY_SECS));
    if dacs.is_empty() {
        eprintln!("No Ether Dream DACs found. The DAC broadcasts to UDP :{ETHERDREAM_BROADCAST_PORT} once/sec — if");
        eprintln!("Wireshark sees those packets but we don't, it's almost always one of:");
        eprintln!("  - Windows Firewall blocking this program's inbound UDP (allow it, or add a rule");
        eprintln!("    for UDP {ETHERDREAM_BROADCAST_PORT}). Capture tools see traffic the firewall drops before us.");
        eprintln!("  - This host has no address on the DAC's subnet (the DAC uses 169.254.x link-local).");
        std::process::exit(1);
    }

    // Determine the FB4 IPs: auto-increment from a single base, or use the explicit list.
    let ips: Vec<Ipv4Addr> = if given.len() == 1 {
        (0..dacs.len()).map(|i| ip_offset(given[0], i as u32)).collect()
    } else {
        given.clone()
    };

    // Ensure each IP exists on the NIC (bind() and ARP require it). Print the alias commands;
    // run them if --add-aliases was passed.
    setup_aliases(&ips, iface.as_deref(), add_aliases);

    let n = dacs.len().min(ips.len());
    if dacs.len() > ips.len() {
        eprintln!("Found {} DACs but only {} FB4 IP(s) — bridging the first {}.", dacs.len(), ips.len(), n);
    }

    for (i, (broadcast, dac_ip)) in dacs.into_iter().take(n).enumerate() {
        let shared: SharedPoints = Arc::new(Mutex::new(Vec::new()));
        let serial = 600_000 + i as u32; // unique fake FB4 serial
        let fb4_ip = ips[i];

        let emu = Arc::new(Fb4Emu { local_ip: fb4_ip, serial, shared: shared.clone(), invert_y: false });
        std::thread::spawn(move || fb4_device::run(emu));
        std::thread::spawn(move || etherdream::run(broadcast, dac_ip, shared));

        println!("Bridged: FB4 {fb4_ip} (serial {serial})  <->  Ether Dream {dac_ip}");
    }

    println!("Running. Point QuickShow/BEYOND at the emulated FB4(s). Ctrl-C to stop.");
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn arg_value(args: &[String], key: &str) -> Option<String> {
    args.iter().position(|a| a == key).and_then(|i| args.get(i + 1)).cloned()
}

/// `base + n`, incrementing the address numerically (e.g. .10 -> .11 -> .12).
fn ip_offset(base: Ipv4Addr, n: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(base).wrapping_add(n))
}

/// The Windows `netsh` command to add an IPv4 alias (assumes a /16, link-local-style mask).
/// Alias setup is only needed on Windows; on other OSes the bridge assumes the IPs already exist.
fn alias_command(ip: Ipv4Addr, iface: &str) -> Vec<String> {
    vec![
        "interface".into(), "ipv4".into(), "add".into(), "address".into(),
        format!("name={iface}"), format!("address={ip}"), "mask=255.255.0.0".into(),
    ]
}

/// Each FB4 IP must exist on the NIC (bind + ARP). On Windows, print the `netsh` alias command for
/// each and run it if `run` is set (needs an elevated/Administrator prompt).
fn setup_aliases(ips: &[Ipv4Addr], iface: Option<&str>, run: bool) {
    if !cfg!(target_os = "windows") {
        return; // alias setup is a Windows-only step here
    }
    let iface = iface.unwrap_or("Ethernet");
    for ip in ips {
        let cmd_args = alias_command(*ip, iface);
        let shown = format!("netsh {}", cmd_args.join(" "));
        if run {
            print!("adding IP alias: {shown} ... ");
            match std::process::Command::new("netsh").args(&cmd_args).status() {
                Ok(s) if s.success() => println!("ok"),
                Ok(s) => println!("exited {s} (may already exist, or needs Administrator)"),
                Err(e) => println!("could not run ({e}) — add it manually"),
            }
        } else {
            println!("  FB4 IP {ip}: ensure it exists on the NIC, e.g.  {shown}");
        }
    }
}

/// Print the host's IPv4 interfaces so the user can confirm one is on the DAC's subnet.
fn print_interfaces() {
    match if_addrs::get_if_addrs() {
        Ok(addrs) => {
            println!("Local IPv4 interfaces:");
            let mut any = false;
            for ifa in addrs {
                if let IpAddr::V4(v4) = ifa.ip() {
                    let ll = if v4.octets()[0] == 169 && v4.octets()[1] == 254 { "  <- link-local" } else { "" };
                    println!("  {:<28} {}{}", ifa.name, v4, ll);
                    any = true;
                }
            }
            if !any {
                println!("  (none found)");
            }
        }
        Err(e) => eprintln!("Could not list interfaces: {e}"),
    }
}

/// Open a UDP listener for Ether Dream broadcasts.
///
/// Bound to 0.0.0.0:7654 with SO_REUSEADDR (and SO_REUSEPORT on unix) so it receives limited
/// broadcasts (255.255.255.255) AND coexists with any other software already listening on the
/// port — a plain bind fails with "address in use" in that case, which is a common reason the DAC
/// is "not seen".
fn open_broadcast_socket() -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_broadcast(true)?;
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, ETHERDREAM_BROADCAST_PORT));
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

/// Collect unique Ether Dream DACs advertised on the network within `window`.
fn discover_dacs(window: Duration) -> Vec<(DacBroadcast, IpAddr)> {
    let sock = match open_broadcast_socket() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Discovery: could not open UDP :{ETHERDREAM_BROADCAST_PORT} listener: {e}");
            eprintln!("  (If this is 'address in use', another program holds the port — we set");
            eprintln!("   SO_REUSEADDR, so this usually means a firewall/permission issue instead.)");
            return Vec::new();
        }
    };
    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();

    let mut seen: HashSet<[u8; 6]> = HashSet::new();
    let mut dacs = Vec::new();
    let mut raw_count: u64 = 0;
    let mut raw_srcs: HashSet<IpAddr> = HashSet::new();
    let deadline = Instant::now() + window;
    let mut buf = [0u8; 1024];
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                raw_count += 1;
                raw_srcs.insert(src.ip());
                if n >= 36 {
                    if let Ok(bc) = DacBroadcast::read_from_bytes(&buf[..n]) {
                        if seen.insert(bc.mac_address) {
                            let ip = src.ip();
                            println!("  found Ether Dream {} at {}", MacAddress(bc.mac_address), ip);
                            dacs.push((bc, ip));
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
            Err(e) => {
                eprintln!("Discovery: recv error: {e}");
                break;
            }
        }
    }
    // Diagnostic: how much actually reached the socket.
    println!(
        "Discovery: {raw_count} datagram(s) on :{ETHERDREAM_BROADCAST_PORT} from {:?}",
        raw_srcs.iter().collect::<Vec<_>>()
    );
    dacs
}
