//! # fb4 — Pangolin FB4 laser controller driver
//!
//! Async discovery, connection, reconnection, and point streaming for Pangolin FB4/FB4E
//! controllers. Also exposes a C ABI (see `include/fb4.h`) for use from C/C++.
//!
//! ## Quick start (Rust)
//! ```no_run
//! use fb4::{Fb4Manager, Config, Point};
//! let mgr = Fb4Manager::new(Config::default()).unwrap();
//! // ... wait a moment for discovery, or add a known device:
//! mgr.add_device("169.254.200.109".parse().unwrap(), 0);
//! let circle: Vec<Point> = (0..200).map(|i| {
//!     let a = std::f64::consts::TAU * i as f64 / 200.0;
//!     Point { x: (a.cos()*10000.0) as i16, y: (a.sin()*10000.0) as i16, r: 0, g: 0, b: 255 }
//! }).collect();
//! for d in mgr.devices() { mgr.set_frame(d.ip, &circle, 20000); }
//! ```
//!
//! Coordinates are signed and centered at the field origin: `(0,0)` = center,
//! `±32767` = the edges. Colors are 8-bit; `(0,0,0)` blanks the beam.

mod clock;
mod discovery;
mod messages;
mod proto;
mod session;

pub mod ffi;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use tokio::runtime::{Handle, Runtime};
use tokio::sync::watch;

pub use proto::Point;

/// Low-level protocol codec, exposed for building tools such as emulators/bridges: key
/// derivation, DES-CBC decrypt, and point-stream parsing.
pub mod codec {
    pub use crate::proto::{
        des_cbc_decrypt, parse_point_stream, session_keybase, tcp_frame_key, transform_nonce,
        turbo_key,
    };
}

use session::{DeviceConfig, FrameData};

/// Default device identity (fingerprint[4] + tail[1]) for the reference FB4E.
pub const DEFAULT_DEVICE_ID: [u8; 5] = [0x69, 0x85, 0xcd, 0x1c, 0x53];

/// How laser frames are streamed to the device. Both paths first do the TCP handshake/config;
/// they differ only in how the point frames themselves are sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Frames over the TCP control connection, session-key encrypted (`0xe02`). Default.
    Tcp,
    /// Frames over UDP as `0dbe`-fragmented turbo frames (`0xe04`), fixed-key. Larger frames,
    /// no per-frame TCP write; the TCP control connection is kept alive with keep-alives.
    UdpTurbo,
}

/// Manager configuration.
#[derive(Clone)]
pub struct Config {
    /// Local NIC IPv4 to bind sockets to (the adapter on the FB4's subnet). Strongly
    /// recommended on multi-homed / link-local hosts. `None` = let the OS choose.
    pub local_ip: Option<Ipv4Addr>,
    /// Device identity used for the `0F0A` stamp (fingerprint[4] + tail[1]).
    pub device_id: [u8; 5],
    /// Frame timeline lead ahead of the device clock, in seconds (default 0.024).
    pub lead: f64,
    /// Default scan rate (points/sec) for the idle/blank frame.
    pub default_pps: u32,
    /// Run periodic network discovery. If `false`, only devices added via
    /// [`Fb4Manager::add_device`] are driven.
    pub discovery: bool,
    /// Frame transport: [`Transport::Tcp`] (default) or [`Transport::UdpTurbo`].
    pub transport: Transport,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            local_ip: None,
            device_id: DEFAULT_DEVICE_ID,
            lead: proto::DEFAULT_LEAD,
            default_pps: proto::DEFAULT_SCAN_RATE,
            discovery: true,
            transport: Transport::Tcp,
        }
    }
}

/// A discovered / connected FB4.
#[derive(Clone, Copy, Debug)]
pub struct DeviceInfo {
    pub ip: Ipv4Addr,
    pub serial: u32,
}

struct Device {
    info: DeviceInfo,
    frame_tx: watch::Sender<Arc<FrameData>>,
    _task: tokio::task::JoinHandle<()>,
}

struct Inner {
    devices: Vec<Device>,
}

/// The top-level driver. Owns an async runtime, runs discovery, and drives one streaming
/// session per FB4 (with automatic reconnection).
pub struct Fb4Manager {
    _rt: Runtime,
    handle: Handle,
    inner: Arc<Mutex<Inner>>,
    config: Config,
}

impl Fb4Manager {
    /// Create a manager: start the runtime and (if enabled) begin discovery.
    pub fn new(config: Config) -> std::io::Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        let handle = rt.handle().clone();
        let inner = Arc::new(Mutex::new(Inner { devices: Vec::new() }));

        // The announce/discovery task always runs (the FB4 needs the presence broadcast even in
        // direct-add mode); auto-adding discovered devices is gated by `config.discovery`.
        {
            let inner2 = inner.clone();
            let cfg = config.clone();
            let h2 = handle.clone();
            handle.spawn(async move { net_loop(inner2, cfg, h2).await });
        }

        Ok(Fb4Manager { _rt: rt, handle, inner, config })
    }

    /// Currently known devices (discovered and/or explicitly added).
    pub fn devices(&self) -> Vec<DeviceInfo> {
        self.inner.lock().unwrap().devices.iter().map(|d| d.info).collect()
    }

    /// Add a device by IP (skips discovery). Idempotent; safe to call repeatedly.
    pub fn add_device(&self, ip: Ipv4Addr, serial: u32) {
        ensure_device(&self.inner, &self.config, &self.handle, ip, serial);
    }

    /// Set the frame streamed to a device by IP. Returns `false` if the IP is unknown.
    /// Call repeatedly (e.g. per animation frame); the latest frame is streamed.
    pub fn set_frame(&self, ip: Ipv4Addr, points: &[Point], pps: u32) -> bool {
        let fd = Arc::new(FrameData::from_points(points, pps.max(1)));
        let g = self.inner.lock().unwrap();
        if let Some(d) = g.devices.iter().find(|d| d.info.ip == ip) {
            d.frame_tx.send_replace(fd);
            true
        } else {
            false
        }
    }

    /// Set the frame for a device by index into [`devices`](Self::devices).
    pub fn set_frame_index(&self, idx: usize, points: &[Point], pps: u32) -> bool {
        let fd = Arc::new(FrameData::from_points(points, pps.max(1)));
        let g = self.inner.lock().unwrap();
        if let Some(d) = g.devices.get(idx) {
            d.frame_tx.send_replace(fd);
            true
        } else {
            false
        }
    }

    /// Blank a device (stream a beam-off frame) without tearing down the session.
    pub fn stop(&self, ip: Ipv4Addr) -> bool {
        self.set_frame(ip, &[Point::default(), Point::default()], self.config.default_pps)
    }
}

fn ensure_device(inner: &Arc<Mutex<Inner>>, config: &Config, handle: &Handle, ip: Ipv4Addr, serial: u32) {
    let mut g = inner.lock().unwrap();
    if let Some(d) = g.devices.iter_mut().find(|d| d.info.ip == ip) {
        if serial != 0 {
            d.info.serial = serial;
        }
        return;
    }
    let (tx, rx) = watch::channel(Arc::new(FrameData::blank(config.default_pps)));
    let dcfg = DeviceConfig {
        local: config.local_ip,
        device_id: config.device_id,
        lead: config.lead,
        transport: config.transport,
    };
    let task = handle.spawn(async move { session::run_session(ip, dcfg, rx).await });
    g.devices.push(Device { info: DeviceInfo { ip, serial }, frame_tx: tx, _task: task });
}

async fn net_loop(inner: Arc<Mutex<Inner>>, config: Config, handle: Handle) {
    // One shared socket handles both presence-announce and discovery for the whole segment.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    handle.spawn(discovery::run_net(config.local_ip, tx));
    while let Some(dev) = rx.recv().await {
        if config.discovery {
            ensure_device(&inner, &config, &handle, dev.ip, dev.serial);
        }
    }
}
