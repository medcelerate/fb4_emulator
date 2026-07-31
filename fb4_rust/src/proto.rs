//! Low-level FB4 protocol: framing, key derivation, DES-CBC frame encryption,
//! point-stream serialization, and clock/timestamp encoding.
//!
//! This module is transport-agnostic — it only produces/consumes byte buffers.
//! See `session.rs` for the connection state machine and `discovery.rs` for discovery.

use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use des::Des;
use generic_array::GenericArray;

// ── Network constants ────────────────────────────────────────────────────────
pub const CONTROL_PORT: u16 = 3348; // TCP control + frames
pub const ANNOUNCE_PORT: u16 = 9022; // UDP announce / presence
pub const DISCOVERY_MCAST: &str = "224.76.78.75";
pub const DISCOVERY_PORT: u16 = 20808;

// ── Protocol constants ───────────────────────────────────────────────────────
pub const MAGIC: [u8; 4] = [0x40, 0xFB, 0x00, 0x00];
pub const KEYBASE_XOR: u32 = 0x2103_1971;
pub const TURBO_XOR: u32 = 0x2909_2023; // fixed constant for the UDP turbo (0xe04) key
pub const TABLE_XOR: u16 = 0xAAAA;
pub const NONCE_MASK: u32 = 0x0FFF_FFFF; // 28-bit session nonce A
pub const COORD_CENTER: i32 = 32768; // unsigned coords centered at 0x8000
pub const INTER_FRAME_GAP: u64 = 0x0020_C49B; // 0.5 ms in acc units (2^32/1000/2)
pub const DEFAULT_LEAD: f64 = 0.024; // 24 ms lead ahead of the FB4 clock
pub const DEFAULT_SCAN_RATE: u32 = 20000;

// 8192-entry x u16 LE key table (a device-family constant).
static KEY_TABLE_BYTES: &[u8] = include_bytes!("../assets/fb4_key_table.bin");

/// `word(idx) = table[idx & 0x1FFF] ^ (idx & 0x1FFF) ^ 0xAAAA`
#[inline]
fn table_word(idx: u32) -> u16 {
    let i = (idx & 0x1FFF) as usize;
    let t = u16::from_le_bytes([KEY_TABLE_BYTES[i * 2], KEY_TABLE_BYTES[i * 2 + 1]]);
    t ^ (i as u16) ^ TABLE_XOR
}

/// `transform(A) = (word(A>>16) << 16) | word(A & 0xFFFF)` — folds the nonce halves.
pub fn transform_nonce(a: u32) -> u32 {
    ((table_word(a >> 16) as u32) << 16) | table_word(a & 0xFFFF) as u32
}

/// The per-connection 64-bit key base (four-word fold of A and B).
pub fn session_keybase(a: u32, b: u32) -> u64 {
    let mut c = b ^ KEYBASE_XOR ^ a;
    let mut w = [0u16; 4];
    for (i, wi) in w.iter_mut().enumerate() {
        c >>= i as u32; // cumulative shift: 0, 1, 3, 6
        *wi = table_word(c & 0x1FFF);
    }
    (w[0] as u64) | ((w[1] as u64) << 16) | ((w[2] as u64) << 32) | ((w[3] as u64) << 48)
}

// ── DES-CBC frame encryption ─────────────────────────────────────────────────

/// TCP per-frame DES key: `[keybase_lo ^ ts_a] : [keybase_hi ^ se_a ^ seq]`.
fn frame_key(keybase: u64, ts_a: u32, se_a: u32, seq: u32) -> [u8; 8] {
    let klo = (keybase as u32) ^ ts_a;
    let khi = ((keybase >> 32) as u32) ^ se_a ^ seq;
    let mut k = [0u8; 8];
    k[0..4].copy_from_slice(&klo.to_le_bytes());
    k[4..8].copy_from_slice(&khi.to_le_bytes());
    k
}

/// UDP turbo per-frame DES key: a table fold of `seq ^ 0x29092023 ^ ts_a ^ se_a ^ param5`.
/// `param5` is the `0dbe` fragment counter (a 16-bit value). No session handshake required.
pub fn turbo_key(seq: u32, ts_a: u32, se_a: u32, param5: u32) -> [u8; 8] {
    let mut h = seq ^ TURBO_XOR ^ ts_a ^ se_a ^ param5;
    let mut k = [0u8; 8];
    for i in 0..4u32 {
        h >>= i; // cumulative shift: 0, 1, 3, 6
        k[(i * 2) as usize..(i * 2 + 2) as usize].copy_from_slice(&table_word(h).to_le_bytes());
    }
    k
}

fn des_encrypt_block(cipher: &Des, block: &[u8; 8]) -> [u8; 8] {
    let mut b = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut b);
    let mut out = [0u8; 8];
    out.copy_from_slice(b.as_slice());
    out
}

/// Encrypt a plaintext point stream with the FB4's DES-CBC construction, given the 8-byte key.
/// `plain` must already be a multiple of 8 bytes (see [`serialize_points`]).
/// Returns `enc(iv) || CBC(plain)`, where `enc(iv)` (block 0) doubles as the IV.
fn des_cbc_with_key(key: [u8; 8], plain: &[u8]) -> Vec<u8> {
    let cipher = Des::new_from_slice(&key).expect("DES key is 8 bytes");

    let mut iv = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut iv);
    let enc_iv = des_encrypt_block(&cipher, &iv);

    let mut out = Vec::with_capacity(8 + plain.len());
    out.extend_from_slice(&enc_iv);
    let mut prev = enc_iv;
    let mut blk = [0u8; 8];
    let mut i = 0;
    while i + 8 <= plain.len() {
        for j in 0..8 {
            blk[j] = plain[i + j] ^ prev[j];
        }
        prev = des_encrypt_block(&cipher, &blk);
        out.extend_from_slice(&prev);
        i += 8;
    }
    out
}

// ── Point stream serialization ───────────────────────────────────────────────

/// A single laser point. Coordinates are signed and centered at the field origin
/// (0,0 = center; +/-32767 = edges). Colors are 8-bit; (0,0,0) blanks the beam.
#[derive(Clone, Copy, Debug, Default)]
pub struct Point {
    pub x: i16,
    pub y: i16,
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

#[inline]
fn to_wire_coord(v: i16) -> u16 {
    (COORD_CENTER + v as i32).clamp(0, 65535) as u16
}

/// Serialize a point list into the FB4 point-stream body:
/// `81 03 count rate <delta points> 84 00 00 00 00 03`, padded (with dwell points)
/// so the whole body is a multiple of 8 with the footer terminal.
pub fn serialize_points(points: &[Point], scan_rate: u32) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(points.len() * 6 + 32);
    buf.push(0x81);
    buf.push(0x03);
    let count_pos = buf.len();
    buf.extend_from_slice(&0u16.to_le_bytes()); // count placeholder (patched below)
    buf.extend_from_slice(&scan_rate.to_le_bytes());

    let (mut px, mut py) = (0u16, 0u16);
    let (mut pr, mut pg, mut pb) = (0u8, 0u8, 0u8);
    for (i, p) in points.iter().enumerate() {
        let force_full = i < 2; // first two points are full keyframes (flags 0x1C)
        let x = to_wire_coord(p.x);
        let y = to_wire_coord(p.y);
        let mut fl = 0u8;
        if force_full || x != px {
            fl |= 0x04;
        }
        if force_full || y != py {
            fl |= 0x08;
        }
        if force_full || p.r != pr || p.g != pg || p.b != pb {
            fl |= 0x10; // 3-color primary only (no secondary color field)
        }
        buf.push(fl);
        if fl & 0x10 != 0 {
            buf.push(p.r);
            buf.push(p.g);
            buf.push(p.b);
        }
        if fl & 0x04 != 0 {
            buf.extend_from_slice(&x.to_le_bytes());
        }
        if fl & 0x08 != 0 {
            buf.extend_from_slice(&y.to_le_bytes());
        }
        px = x;
        py = y;
        pr = p.r;
        pg = p.g;
        pb = p.b;
    }

    // Footer-terminal alignment: pad with dwell (0x00) points so header(8)+points+footer(6)
    // is a multiple of 8, keeping the footer as the frame's final bytes. Count the pads.
    let mut pad = 0u16;
    while (buf.len() + 6) % 8 != 0 {
        buf.push(0x00);
        pad += 1;
    }
    let count = points.len() as u16 + pad;
    buf[count_pos..count_pos + 2].copy_from_slice(&count.to_le_bytes());

    buf.extend_from_slice(&[0x84, 0x00, 0x00, 0x00, 0x00, 0x03]); // terminator + footer
    buf
}

// ── Frame message assembly ───────────────────────────────────────────────────

/// Build a complete TCP laser frame message (`fmt 0x02`, `40fb` header + DES-CBC body).
/// `ts_acc` is the frame's timeline accumulator (see [`clock_fields`]); `span_acc` is the
/// frame span (`(count<<32)/scan_rate`); `seq` is the global counter.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_frame(keybase: u64, seq: u32, ts_acc: u64, span_acc: u64, body: &[u8]) -> Vec<u8> {
    let (ts_a, se_a) = clock_fields(ts_acc);
    let (ts_b, se_b) = clock_fields(ts_acc + span_acc);

    let cipher_body = des_cbc_with_key(frame_key(keybase, ts_a, se_a, seq), body);
    let size = 32 + cipher_body.len();

    let mut msg = vec![0u8; 32];
    msg[0..4].copy_from_slice(&MAGIC);
    msg[4] = 0x02; // fmt: TCP laser frame (0xe02)
    msg[5] = 0x0E;
    msg[6..8].copy_from_slice(&0x0003u16.to_le_bytes()); // flags
    msg[8..12].copy_from_slice(&(size as u32).to_le_bytes());
    msg[12..16].copy_from_slice(&seq.to_le_bytes());
    msg[16..20].copy_from_slice(&ts_a.to_le_bytes());
    msg[20..24].copy_from_slice(&se_a.to_le_bytes());
    msg[24..28].copy_from_slice(&ts_b.to_le_bytes());
    msg[28..32].copy_from_slice(&se_b.to_le_bytes());
    msg.extend_from_slice(&cipher_body);
    msg
}

/// Maximum inner-frame bytes carried per `0dbe` UDP fragment.
const UDP_CHUNK: usize = 1452;

/// Build a UDP "turbo" laser frame (`fmt 0x04`) and split it into `0dbe` fragment datagrams.
/// `seq` is the inner-frame header counter; `framenum` is the fragment/frame counter used as the
/// turbo key's `param5` (masked to 16 bits, as it appears on the wire). Returns the datagrams
/// in order — send each over the UDP socket to `:3348`.
pub fn build_udp_turbo_frames(seq: u32, framenum: u32, ts_acc: u64, span_acc: u64, body: &[u8]) -> Vec<Vec<u8>> {
    let (ts_a, se_a) = clock_fields(ts_acc);
    let (ts_b, se_b) = clock_fields(ts_acc + span_acc);
    let param5 = framenum & 0xFFFF;

    let cipher_body = des_cbc_with_key(turbo_key(seq, ts_a, se_a, param5), body);
    let size = 32 + cipher_body.len();

    let mut inner = vec![0u8; 32];
    inner[0..4].copy_from_slice(&MAGIC);
    inner[4] = 0x04; // fmt: UDP turbo laser frame (0xe04)
    inner[5] = 0x0E;
    inner[6..8].copy_from_slice(&0x0003u16.to_le_bytes());
    inner[8..12].copy_from_slice(&(size as u32).to_le_bytes());
    inner[12..16].copy_from_slice(&seq.to_le_bytes());
    inner[16..20].copy_from_slice(&ts_a.to_le_bytes());
    inner[20..24].copy_from_slice(&se_a.to_le_bytes());
    inner[24..28].copy_from_slice(&ts_b.to_le_bytes());
    inner[28..32].copy_from_slice(&se_b.to_le_bytes());
    inner.extend_from_slice(&cipher_body);

    // Fragment into 0dbe datagrams. Header (16 bytes): magic 0dbe, 01 10 03 00, last-frag flag,
    // 00, u16(16+seglen), u16(offset), u16(counter=param5), frag index, total frags.
    let total = inner.len();
    let nfrags = ((total + UDP_CHUNK - 1) / UDP_CHUNK).max(1);
    let mut pkts = Vec::with_capacity(nfrags);
    let mut off = 0usize;
    let mut idx = 0usize;
    while off < total {
        let end = (off + UDP_CHUNK).min(total);
        let seg = &inner[off..end];
        let mut out = vec![0u8; 16 + seg.len()];
        out[0..4].copy_from_slice(&[0x0d, 0xbe, 0x01, 0x10]);
        out[4] = 0x03;
        out[5] = 0x00;
        if idx == nfrags - 1 {
            out[6] = 0x01; // final fragment
        }
        out[7] = 0x00;
        out[8..10].copy_from_slice(&((16 + seg.len()) as u16).to_le_bytes());
        out[10..12].copy_from_slice(&(off as u16).to_le_bytes());
        out[12..14].copy_from_slice(&(param5 as u16).to_le_bytes());
        out[14] = idx as u8;
        out[15] = nfrags as u8;
        out[16..].copy_from_slice(seg);
        pkts.push(out);
        off = end;
        idx += 1;
    }
    pkts
}

/// Frame span in accumulator units: `(point_count << 32) / scan_rate`.
pub fn frame_span_acc(count: usize, scan_rate: u32) -> u64 {
    ((count as u64) << 32) / (scan_rate as u64)
}

// ── Decoding (for emulation / verification) ──────────────────────────────────

/// The TCP per-frame DES key, exposed for decoding frames (device-side / tests).
pub fn tcp_frame_key(keybase: u64, ts_a: u32, se_a: u32, seq: u32) -> [u8; 8] {
    frame_key(keybase, ts_a, se_a, seq)
}

fn des_decrypt_block(cipher: &Des, block: &[u8; 8]) -> [u8; 8] {
    let mut b = GenericArray::clone_from_slice(block);
    cipher.decrypt_block(&mut b);
    let mut out = [0u8; 8];
    out.copy_from_slice(b.as_slice());
    out
}

/// Inverse of the CBC construction in [`build_tcp_frame`] / [`build_udp_turbo_frames`]:
/// `cipher = enc(iv) || CBC(plain)`; recovers `plain`. Block 0 (the encrypted IV) is the IV.
pub fn des_cbc_decrypt(key: [u8; 8], cipher_body: &[u8]) -> Vec<u8> {
    let cipher = Des::new_from_slice(&key).expect("DES key is 8 bytes");
    let ct = &cipher_body[..cipher_body.len() - cipher_body.len() % 8];
    let mut out = Vec::with_capacity(ct.len());
    let mut block = [0u8; 8];
    let mut i = 8; // skip block 0 (encrypted IV)
    while i + 8 <= ct.len() {
        block.copy_from_slice(&ct[i..i + 8]);
        let dec = des_decrypt_block(&cipher, &block);
        for j in 0..8 {
            out.push(dec[j] ^ ct[i - 8 + j]); // XOR previous ciphertext block
        }
        i += 8;
    }
    out
}

/// Parse a decrypted point-stream body (`81 03 count rate <delta points> 84 …`) back into
/// points. Wire coordinates (unsigned, centered 32768) are converted to the signed [`Point`]
/// convention (centered 0). Returns `(scan_rate, points)`.
pub fn parse_point_stream(body: &[u8]) -> (u32, Vec<Point>) {
    if body.len() < 8 || body[0] != 0x81 {
        return (0, Vec::new());
    }
    let scan_rate = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    let mut pts = Vec::new();
    let (mut x, mut y) = (0u16, 0u16);
    let (mut r, mut g, mut b) = (0u8, 0u8, 0u8);
    let mut i = 8;
    while i < body.len() {
        let f = body[i];
        if f & 0x80 != 0 {
            break; // 0x84 terminator (or another control block)
        }
        i += 1;
        if f & 0x10 != 0 && i + 3 <= body.len() {
            r = body[i];
            g = body[i + 1];
            b = body[i + 2];
            i += 3;
        }
        if f & 0x04 != 0 && i + 2 <= body.len() {
            x = u16::from_le_bytes([body[i], body[i + 1]]);
            i += 2;
        }
        if f & 0x08 != 0 && i + 2 <= body.len() {
            y = u16::from_le_bytes([body[i], body[i + 1]]);
            i += 2;
        }
        if f & 0x02 != 0 && i + 3 <= body.len() {
            i += 3; // secondary color (6-color mode) — skip
        }
        pts.push(Point {
            x: (x as i32 - COORD_CENTER) as i16,
            y: (y as i32 - COORD_CENTER) as i16,
            r,
            g,
            b,
        });
    }
    (scan_rate, pts)
}

// ── Clock / timestamp encoding ───────────────────────────────────────────────

/// Split a 64-bit timeline accumulator into header fields `(ts_a, se_a)`:
/// `ts_a = acc_lo / 2`, `se_a = acc_hi`.
#[inline]
pub fn clock_fields(acc: u64) -> (u32, u32) {
    (((acc & 0xFFFF_FFFF) as u32) / 2, (acc >> 32) as u32)
}

/// Seconds -> accumulator: `acc = round(seconds * 2^32)`.
#[inline]
pub fn secs_to_acc(seconds: f64) -> u64 {
    (seconds * 4_294_967_296.0) as u64
}

/// Delphi `TDateTime` for the 0F0A stamp: days since 1899-12-30 plus fractional day.
pub fn tdatetime(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32, nanos: u32) -> f64 {
    let days = days_from_civil(year, month as i32, day as i32);
    let secs = hour as f64 * 3600.0 + min as f64 * 60.0 + sec as f64 + nanos as f64 / 1e9;
    days as f64 + 25569.0 + secs / 86400.0
}

/// Days from civil date to the Unix epoch (Howard Hinnant's algorithm).
fn days_from_civil(mut y: i32, m: i32, d: i32) -> i64 {
    if m <= 2 {
        y -= 1;
    }
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146097 + doe - 719468
}
