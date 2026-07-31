//! Convert decoded FB4 points into Ether Dream `DacPoint`s.
//!
//! FB4 (via the `fb4` codec) yields points with signed `i16` coordinates centered at the field
//! origin and 8-bit RGB. Ether Dream wants signed `i16` coordinates (same convention) and
//! full-scale 16-bit color. So coordinates pass through; color is scaled 8→16 bit (`v * 257`).

use ether_dream::protocol::DacPoint;
use fb4::Point;

/// Scale an 8-bit channel to full-scale 16-bit (0..255 -> 0..65535).
#[inline]
fn c16(v: u8) -> u16 {
    (v as u16) * 257
}

/// Convert one FB4 point to an Ether Dream point.
#[inline]
pub fn to_dac_point(p: &Point, invert_y: bool) -> DacPoint {
    let y = if invert_y { p.y.saturating_neg() } else { p.y };
    DacPoint {
        control: 0,
        x: p.x,
        y,
        r: c16(p.r),
        g: c16(p.g),
        b: c16(p.b),
        i: c16(p.r.max(p.g).max(p.b)), // intensity = brightest channel
        u1: 0,
        u2: 0,
    }
}

/// Convert a full FB4 frame to Ether Dream points.
pub fn to_dac_points(points: &[Point], invert_y: bool) -> Vec<DacPoint> {
    points.iter().map(|p| to_dac_point(p, invert_y)).collect()
}
