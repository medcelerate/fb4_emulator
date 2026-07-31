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
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ether_dream::dac::MacAddress;
use ether_dream::protocol::DacBroadcast;

use etherdream::SharedPoints;
use fb4_device::Fb4Emu;

const DISCOVERY_SECS: u64 = 4;

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

    println!("Discovering Ether Dream DACs for {DISCOVERY_SECS}s...");
    let dacs = discover_dacs(Duration::from_secs(DISCOVERY_SECS));
    if dacs.is_empty() {
        eprintln!("No Ether Dream DACs found. (Are they powered and on this subnet?)");
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

/// Collect unique Ether Dream DACs advertised on the network within `window`.
fn discover_dacs(window: Duration) -> Vec<(DacBroadcast, IpAddr)> {
    let (tx, rx) = std::sync::mpsc::channel::<(DacBroadcast, IpAddr)>();
    std::thread::spawn(move || {
        if let Ok(iter) = ether_dream::recv_dac_broadcasts() {
            for res in iter {
                if let Ok((bc, addr)) = res {
                    if tx.send((bc, addr.ip())).is_err() {
                        return;
                    }
                }
            }
        }
    });

    let mut seen: HashSet<[u8; 6]> = HashSet::new();
    let mut dacs = Vec::new();
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(500))) {
            Ok((bc, ip)) => {
                if seen.insert(bc.mac_address) {
                    println!("  found Ether Dream {} at {}", MacAddress(bc.mac_address), ip);
                    dacs.push((bc, ip));
                }
            }
            Err(_) => {}
        }
    }
    dacs
}
