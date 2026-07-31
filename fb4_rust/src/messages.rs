//! Fixed control/handshake message templates and their builders.
//!
//! Templates are the byte-exact setup messages the FB4 expects during the config phase.
//! Builders clone a template and patch the per-message fields (sequence counter,
//! timestamps, nonce, identity).

use crate::proto;

// Config/handshake templates (hex). `seq` (bytes 0x0C..0x10) is patched per send.
const T_0101: &str = "40fb000001010000300200000100000000000000000000000000000000000000444e59420505ee07df07031591aba6026b934ef2c5f2e5f7ede9eeb75d701068781be44154cc1ab0c403a5a93e2c12b744aa5584557dbcf6a0b0d527f70668b2bd81e44bc3c4d87c60654ffa33a7380c50542ccbd386286219a52e6f0bf9ce405481068f65f706eb8533cbfb7d4c8f45833c83276fd25e2c7640abf3da8de93962bfd9d477849bba439e6f3837754214b77e5245f95b995d3aecc4e8d4b7e558f3533b35debb95ba0fca54109b33fcbfa9aed42be84c1b0e4c09b457852273edf7c9451f2325f5d0c0d258b50d49f121fbd287315605236ef4e77c1ea029c6de41215955707bc0f494c31d310f2ed8a632632d04fe1cfac1e3d1deecfbde96a187ce1aec95ad00342b9c075d4b0ee951b650cca34559ec5e2a00634a930a204265bb725207dcbfb0875440e88ec9e2b8d5fab0652fb947ae3ea3558e852223615a428d41db61119d12d3b559c7f20704c13966ef656c5d32faddc3e71555e132ca33dbcdcfc4094497f71a040ed11cf38f56c14037d7857b9dc78257a786277cfbd2125e42c5c0024991e11597626bd7380fd8a694921c32c96a29b1c84a3c9c1ad829ac38575547b866468cc353c397979507c7156b7e0f84c613a127eaf28134715cc6599ee798e02e453c110a76ab7190e79bf06112e238ce60a395659fb03e3d2d0feff89c8f1c97a0cb269c5922691a616f06aa3b90b369f2080a6a18400e505f3decf19dd82c43ddb7cad6c69d";
const T_070A: &str = "40fb0000070a0000200000000300000000010000000000000000000000000000";
const T_080A: &str = "40fb0000080a0000200000000400000000000000000000000000000000000000";
const T_3100: &str = "40fb000031000000200000000500000000000000000000000000000000000000";
const T_030A: &str = "40fb0000030a0000200000000600000000000000000000000000000000000000";
const T_040A: &str = "40fb0000040a0000200000000700000000000000000000000000000000000000";
const T_0F0A: &str = "40fb00000f0a00002000000008000000d7107e263991e6406985cd1c53000000";
const T_010D: &str = "40fb0000010d0000200000000a0000000a000000000000000000000000000000";
const T_0200: &str = "40fb000002000000200000001f00000000000000000000000000000000000000";
const T_0000: &str = "40fb000000000000200000000200000000000000000000000000000000000000";
const T_0100: &str = "40fb000001000000200000003b01000000000000000000000000000000000000";

pub fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Set the header `seq` field (offset 0x0C).
pub fn set_seq(buf: &mut [u8], seq: u32) {
    put_u32(buf, 0x0C, seq);
}

/// Build the `0101` handshake with a fresh 28-bit nonce `A`. Returns (message, A).
pub fn build_handshake(seq: u32) -> (Vec<u8>, u32) {
    let mut p = hex_decode(T_0101);
    // Identity block (fixed): tag + version + build date.
    p[0x20..0x24].copy_from_slice(&[0x30, 0x33, 0x53, 0x51]); // "QS30"
    p[0x24..0x28].copy_from_slice(&[0x05, 0x05, 0x92, 0x07]);
    p[0x28..0x2C].copy_from_slice(&[0xdf, 0x07, 0x03, 0x15]);
    // Fresh random 28-bit nonce A.
    let mut a4 = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut a4);
    let a = u32::from_le_bytes(a4) & proto::NONCE_MASK;
    put_u32(&mut p, 0x2C, a);
    // Random padding body.
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut p[0x30..]);
    set_seq(&mut p, seq);
    (p, a)
}

/// Fields parsed from the FB4's `0181` handshake reply.
pub struct HandshakeReply {
    pub model: [u8; 4],
    pub serial: u32,
    pub b: u32,
    pub clock_acc: u64, // device clock at reply time (0 if not present)
}

/// Locate and parse a `0181` reply (`fmt 0x01 / subtype 0x81`) inside a buffer of
/// concatenated `40fb` messages.
pub fn parse_handshake_reply(buf: &[u8]) -> Option<HandshakeReply> {
    let mut i = 0;
    while i + 0x54 <= buf.len() {
        if buf[i] == 0x40 && buf[i + 1] == 0xFB && buf[i + 4] == 0x01 && buf[i + 5] == 0x81 {
            let m = &buf[i..];
            let mut model = [0u8; 4];
            model.copy_from_slice(&m[0x20..0x24]);
            let serial = u32::from_le_bytes([m[0x34], m[0x35], m[0x36], m[0x37]]);
            let b = u32::from_le_bytes([m[0x50], m[0x51], m[0x52], m[0x53]]);
            let cts = u32::from_le_bytes([m[0x10], m[0x11], m[0x12], m[0x13]]);
            let cse = u32::from_le_bytes([m[0x14], m[0x15], m[0x16], m[0x17]]);
            let clock_acc = if cse != 0 {
                ((cse as u64) << 32) | ((cts as u64) * 2)
            } else {
                0
            };
            return Some(HandshakeReply { model, serial, b, clock_acc });
        }
        i += 1;
    }
    None
}

fn template(hex: &str, seq: u32) -> Vec<u8> {
    let mut p = hex_decode(hex);
    set_seq(&mut p, seq);
    p
}

// Config-phase messages in the order they are sent.
pub fn cfg_070a(seq: u32) -> Vec<u8> { template(T_070A, seq) }
pub fn cfg_080a(seq: u32) -> Vec<u8> { template(T_080A, seq) }
pub fn cfg_3100(seq: u32) -> Vec<u8> { template(T_3100, seq) }
pub fn cfg_030a(seq: u32) -> Vec<u8> { template(T_030A, seq) }
pub fn cfg_040a(seq: u32) -> Vec<u8> { template(T_040A, seq) }
pub fn keepalive(seq: u32) -> Vec<u8> { template(T_0000, seq) }
pub fn disable_output(seq: u32) -> Vec<u8> { template(T_0100, seq) }
pub fn enable_output(seq: u32) -> Vec<u8> { template(T_0200, seq) }

/// `010d` per-channel setup (channels 0..8), patching the channel byte at 0x1C.
pub fn cfg_010d(seq: u32, channel: u8) -> Vec<u8> {
    let mut p = template(T_010D, seq);
    p[0x1C] = channel;
    p
}

/// `050a`/`060a` clock set. `code` = 0x05 (date: y,m,d) or 0x06 (time: h,m,s).
pub fn set_clock(seq: u32, code: u8, a: u32, b: u32, c: u32) -> Vec<u8> {
    let mut p = vec![0u8; 0x20];
    p[0] = 0x40;
    p[1] = 0xFB;
    p[4] = code;
    p[5] = 0x0A;
    put_u32(&mut p, 8, 0x20);
    set_seq(&mut p, seq);
    put_u32(&mut p, 0x10, a);
    put_u32(&mut p, 0x14, b);
    put_u32(&mut p, 0x18, c);
    p
}

/// `0F0A` identity stamp: 5-byte device id (fingerprint[4] + tail[1]) + a live TDateTime.
pub fn build_0f0a(seq: u32, device_id: &[u8; 5], tdatetime: f64) -> Vec<u8> {
    let mut p = template(T_0F0A, seq);
    p[0x10..0x18].copy_from_slice(&tdatetime.to_le_bytes());
    p[0x18..0x1C].copy_from_slice(&device_id[0..4]);
    p[0x1C] = device_id[4];
    p[0x1D] = 0;
    p[0x1E] = 0;
    p[0x1F] = 0;
    p
}
