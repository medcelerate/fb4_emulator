//! Shared per-device timeline clock.
//!
//! The FB4 reports its scan-engine clock in the handshake reply; frames and announces must
//! be stamped in that domain. `ClockBase` holds the captured base and extrapolates it with
//! elapsed real time. Before the base is set it returns elapsed-since-start (a bootstrap
//! domain used by the announce until the handshake syncs it).

use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::proto::secs_to_acc;

#[derive(Clone)]
pub struct ClockBase(Arc<Mutex<Inner>>);

struct Inner {
    base: u64,
    wall: Instant,
    set: bool,
}

impl ClockBase {
    pub fn new() -> Self {
        ClockBase(Arc::new(Mutex::new(Inner {
            base: 0,
            wall: Instant::now(),
            set: false,
        })))
    }

    /// Current timeline accumulator in the device clock domain.
    pub fn now(&self) -> u64 {
        let g = self.0.lock().unwrap();
        let adv = secs_to_acc(g.wall.elapsed().as_secs_f64());
        if g.set {
            g.base.wrapping_add(adv)
        } else {
            adv
        }
    }

    /// Capture the device clock (from the handshake reply) as the new base.
    pub fn set_base(&self, acc: u64) {
        let mut g = self.0.lock().unwrap();
        g.base = acc;
        g.wall = Instant::now();
        g.set = true;
    }

    /// Forget the base (on disconnect); the next handshake re-syncs it.
    pub fn unset(&self) {
        self.0.lock().unwrap().set = false;
    }
}

impl Default for ClockBase {
    fn default() -> Self {
        Self::new()
    }
}
