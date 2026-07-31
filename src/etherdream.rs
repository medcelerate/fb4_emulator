//! Drive one Ether Dream DAC, continuously feeding it points from a shared buffer that the FB4
//! emulator updates as frames arrive from QuickShow/BEYOND.

use std::error::Error;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ether_dream::dac;
use ether_dream::protocol::{DacBroadcast, DacPoint};

/// The current frame of Ether Dream points, shared between the FB4 emulator (writer) and the
/// DAC driver (reader). Empty = nothing to show yet (the driver emits blanked points).
pub type SharedPoints = Arc<Mutex<Vec<DacPoint>>>;

fn blank_point() -> DacPoint {
    DacPoint { control: 0, x: 0, y: 0, r: 0, g: 0, b: 0, i: 0, u1: 0, u2: 0 }
}

/// How many points the DAC can accept right now (buffer capacity minus current fullness).
fn room(dac: &dac::Dac) -> usize {
    let cap = dac.buffer_capacity as usize;
    let full = dac.status.buffer_fullness as usize;
    cap.saturating_sub(full).saturating_sub(1)
}

/// Run one DAC forever: (re)connect and stream, cycling the shared frame's points to keep the
/// DAC buffer full. Reconnects on error.
pub fn run(broadcast: DacBroadcast, dac_ip: IpAddr, shared: SharedPoints) {
    loop {
        if let Err(e) = drive(&broadcast, dac_ip, &shared) {
            eprintln!("[etherdream {dac_ip}] stream ended: {e}; reconnecting in 2s");
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn drive(broadcast: &DacBroadcast, dac_ip: IpAddr, shared: &SharedPoints) -> Result<(), Box<dyn Error>> {
    let mut stream = dac::stream::connect(broadcast, dac_ip)?;
    // Stream at up to ~30 kpps, capped by the DAC's own maximum.
    let pps: u32 = (stream.dac().max_point_rate).min(30_000).max(1_000);
    stream.queue_commands().prepare_stream().submit()?;

    let mut cursor = 0usize;
    let mut begun = false;

    loop {
        let mut n = room(stream.dac());
        if n == 0 {
            // Buffer full — a ping reads a fresh status and paces us.
            stream.queue_commands().ping().submit()?;
            continue;
        }
        n = n.min(1000); // bounded batch

        let frame = shared.lock().unwrap().clone();
        let batch: Vec<DacPoint> = if frame.is_empty() {
            cursor = 0;
            vec![blank_point(); n]
        } else {
            let out = (0..n).map(|k| frame[(cursor + k) % frame.len()]).collect();
            cursor = (cursor + n) % frame.len();
            out
        };

        let q = stream.queue_commands().data(batch.iter().copied());
        let q = if !begun { begun = true; q.begin(0, pps) } else { q };
        q.submit()?;
    }
}
