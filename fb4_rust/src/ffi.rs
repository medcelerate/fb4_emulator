//! C ABI for the fb4 driver. See `include/fb4.h` (C) and `include/fb4.hpp` (C++).
//!
//! All functions are index-centric: discover devices, read the count, then address a device
//! by its index into the current device list. Returns use `0` for success and negative for
//! error unless noted. The manager is thread-safe; call from any thread.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;

use crate::{Config, Fb4Manager, Point, Transport};

/// A laser point for the C ABI. Coordinates are signed, centered at the field origin
/// (`0,0` = center; `±32767` = edges). Colors are 8-bit; `(0,0,0)` blanks the beam.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Fb4Point {
    pub x: i16,
    pub y: i16,
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl From<Fb4Point> for Point {
    fn from(p: Fb4Point) -> Point {
        Point { x: p.x, y: p.y, r: p.r, g: p.g, b: p.b }
    }
}

/// Create a manager with default configuration (discovery on). Returns null on failure.
#[no_mangle]
pub extern "C" fn fb4_new() -> *mut Fb4Manager {
    make(Config::default())
}

/// Create a manager bound to a specific local NIC IPv4 (recommended). `local_ip` may be null.
#[no_mangle]
pub extern "C" fn fb4_new_local(local_ip: *const c_char) -> *mut Fb4Manager {
    let mut cfg = Config::default();
    if let Some(s) = cstr(local_ip) {
        cfg.local_ip = s.parse().ok();
    }
    make(cfg)
}

/// Create a manager with explicit options: optional local NIC IPv4 (may be null) and the
/// transport (`0` = TCP `0xe02`, `1` = UDP turbo `0xe04`). Returns null on failure.
#[no_mangle]
pub extern "C" fn fb4_new_ex(local_ip: *const c_char, udp_turbo: c_int) -> *mut Fb4Manager {
    let mut cfg = Config::default();
    if let Some(s) = cstr(local_ip) {
        cfg.local_ip = s.parse().ok();
    }
    cfg.transport = if udp_turbo != 0 { Transport::UdpTurbo } else { Transport::Tcp };
    make(cfg)
}

fn make(cfg: Config) -> *mut Fb4Manager {
    match Fb4Manager::new(cfg) {
        Ok(m) => Box::into_raw(Box::new(m)),
        Err(_) => ptr::null_mut(),
    }
}

/// Destroy a manager and stop all sessions.
///
/// # Safety
/// `m` must be a pointer returned by `fb4_new*` and not used afterward.
#[no_mangle]
pub unsafe extern "C" fn fb4_free(m: *mut Fb4Manager) {
    if !m.is_null() {
        drop(Box::from_raw(m));
    }
}

/// Number of currently known devices.
///
/// # Safety
/// `m` must be a valid manager pointer.
#[no_mangle]
pub unsafe extern "C" fn fb4_device_count(m: *mut Fb4Manager) -> c_int {
    match m.as_ref() {
        Some(m) => m.devices().len() as c_int,
        None => 0,
    }
}

/// Serial number of device `idx`, or 0 if out of range.
///
/// # Safety
/// `m` must be a valid manager pointer.
#[no_mangle]
pub unsafe extern "C" fn fb4_device_serial(m: *mut Fb4Manager, idx: c_int) -> u32 {
    match m.as_ref() {
        Some(m) => m.devices().get(idx as usize).map(|d| d.serial).unwrap_or(0),
        None => 0,
    }
}

/// Write device `idx`'s IPv4 string into `buf` (NUL-terminated). Returns the string length,
/// or -1 on error / out of range.
///
/// # Safety
/// `m` must be valid; `buf` must point to at least `buflen` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn fb4_device_ip(m: *mut Fb4Manager, idx: c_int, buf: *mut c_char, buflen: c_int) -> c_int {
    let m = match m.as_ref() {
        Some(m) => m,
        None => return -1,
    };
    let devs = m.devices();
    let dev = match devs.get(idx as usize) {
        Some(d) => d,
        None => return -1,
    };
    let s = match CString::new(dev.ip.to_string()) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let bytes = s.as_bytes_with_nul();
    if buf.is_null() || (buflen as usize) < bytes.len() {
        return -1;
    }
    ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buf, bytes.len());
    (bytes.len() - 1) as c_int
}

/// Add a device by IPv4 string (direct mode, skips discovery). Returns 0 on success.
///
/// # Safety
/// `m` must be valid; `ip` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn fb4_add_device(m: *mut Fb4Manager, ip: *const c_char, serial: u32) -> c_int {
    let m = match m.as_ref() {
        Some(m) => m,
        None => return -1,
    };
    match cstr(ip).and_then(|s| s.parse().ok()) {
        Some(addr) => {
            m.add_device(addr, serial);
            0
        }
        None => -1,
    }
}

/// Stream `pts` (length `n`) to device `idx` at `pps` points/sec. The frame is streamed
/// continuously until replaced; call again per animation frame. Returns 0 on success.
///
/// # Safety
/// `m` must be valid; `pts` must point to `n` `Fb4Point`s.
#[no_mangle]
pub unsafe extern "C" fn fb4_set_frame(m: *mut Fb4Manager, idx: c_int, pts: *const Fb4Point, n: usize, pps: u32) -> c_int {
    let m = match m.as_ref() {
        Some(m) => m,
        None => return -1,
    };
    if pts.is_null() && n != 0 {
        return -1;
    }
    let slice = if n == 0 { &[][..] } else { std::slice::from_raw_parts(pts, n) };
    let points: Vec<Point> = slice.iter().copied().map(Into::into).collect();
    if m.set_frame_index(idx as usize, &points, pps) {
        0
    } else {
        -1
    }
}

/// Blank device `idx` (beam off) without disconnecting. Returns 0 on success.
///
/// # Safety
/// `m` must be a valid manager pointer.
#[no_mangle]
pub unsafe extern "C" fn fb4_stop(m: *mut Fb4Manager, idx: c_int) -> c_int {
    let m = match m.as_ref() {
        Some(m) => m,
        None => return -1,
    };
    let blank: [Point; 2] = [Point { x: 0, y: 0, r: 0, g: 0, b: 0 }; 2];
    if m.set_frame_index(idx as usize, &blank, crate::proto::DEFAULT_SCAN_RATE) {
        0
    } else {
        -1
    }
}

fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok()
}
