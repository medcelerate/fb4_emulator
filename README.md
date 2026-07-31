# fb4_bridge — drive Ether Dream DACs from QuickShow / BEYOND

A protocol bridge. It **emulates FB4 laser controllers** toward Pangolin QuickShow/BEYOND, and
forwards the laser stream those programs send to real **Ether Dream** DACs on the network.

```
QuickShow / BEYOND  ──FB4 protocol──▶  fb4_bridge (fake FB4s)  ──Ether Dream protocol──▶  Ether Dream DAC(s)
```

For each Ether Dream DAC it finds, it presents one emulated FB4E. QuickShow/BEYOND discovers and
connects to the emulated FB4, and every frame it streams (TCP `0xe02` or UDP turbo `0xe04`) is
decrypted, decoded to points, converted, and pushed to the paired DAC.

## How it works

- **Ether Dream side** (solid, via the `ether-dream` crate): discovers DACs (UDP broadcast),
  connects (TCP :7765), and continuously feeds points, keeping the DAC's buffer full.
- **FB4 decode** (known cold from our reverse engineering, in the `fb4` crate's `codec`):
  session-key / turbo-key derivation, DES-CBC decrypt, and point-stream parsing.
- **Conversion**: FB4 points (signed, centered; 8-bit color) → Ether Dream `DacPoint`s (signed,
  centered; 16-bit color, scaled ×257).
- **FB4 emulation** (the device side): ASDP presence announce so QuickShow/BEYOND discover it; a
  TCP server that answers the `0101` handshake (computing the device's `B = transform(A) ^ serial`
  so the session key matches), replays the captured config replies, decrypts incoming frames, and
  emits `0d8a` scan-out acks so the host believes it is scanning. Turbo `0dbe` frames are handled
  over UDP.

Each emulated FB4 gets a unique serial (`600000 + n`).

## Build

```
cargo build --release
```

The `fb4` library is a git dependency on [`medcelerate/FB4`](https://github.com/medcelerate/FB4),
so a plain build fetches it automatically — no local checkout needed. (For local work against a
sibling copy of the library, uncomment the `[patch]` block in `Cargo.toml`.)

> The library repo must include the `codec` module the emulator uses
> (`fb4::codec::{transform_nonce, session_keybase, tcp_frame_key, des_cbc_decrypt,
> parse_point_stream, turbo_key}`). Push those before building.

### CI

`.github/workflows/build-emulator.yml` builds the Windows emulator on every push/PR: it checks out
this repo, pulls `fb4` from git, builds release, and uploads `fb4_bridge-windows-x64.zip` as an
artifact. Pushing a `v*` tag also attaches the zip to a GitHub Release.

If the library repo is **private**, authenticate with an SSH deploy key (more reliable in CI than
HTTP credential helpers, especially on Windows):

1. Generate a keypair: `ssh-keygen -t ed25519 -f fb4_deploy -N ""`.
2. In `medcelerate/FB4` → Settings → Deploy keys, add `fb4_deploy.pub` (read-only).
3. In this repo → Settings → Secrets → Actions, add `KEY_S` = the private key (`fb4_deploy`).

The key **must have no passphrase** (`-N ""` above). CI writes it to a file, points git's ssh at
it, and rewrites the git transport to SSH (`CARGO_NET_GIT_FETCH_WITH_CLI` makes cargo use the git
CLI). It deliberately avoids ssh-agent, which is unreliable on Windows runners. If the repo is
public, omit the secret entirely — the SSH steps are skipped and the build fetches over HTTPS.

## Run

```
fb4_bridge <base-ip> [--iface NAME] [--add-aliases]      # auto-increment from a base
fb4_bridge <fb4-ip-1> <fb4-ip-2> ...                     # explicit list
```

With **one base IP**, the bridge auto-assigns one FB4 IP per discovered DAC by incrementing the
base — e.g. `169.254.100.10` → `.10`, `.11`, `.12`, one per DAC. Example (single DAC):

```
fb4_bridge 169.254.100.10
```

### Each FB4 IP must exist on the NIC

Every emulated FB4 is a separate network device that QuickShow/BEYOND connects to at `ip:3348`, so
each IP has to be a real address on your adapter (otherwise `bind()` fails and ARP won't resolve).
Auto-increment picks the addresses; you still add them to the NIC.

On **Windows**, the bridge prints the exact `netsh` command for each IP, and can run them for you
with `--add-aliases` from an **Administrator** prompt:

```
fb4_bridge 169.254.100.10 --iface "Ethernet" --add-aliases
```

That runs, per DAC:

```
netsh interface ipv4 add address name=Ethernet address=169.254.100.11 mask=255.255.0.0
```

(Use `--iface` to match your adapter's name, e.g. `"Local Area Connection"`. On non-Windows OSes
the alias step is skipped — configure the IPs yourself.)

Then in QuickShow/BEYOND, run discovery — the emulated FB4E(s) should appear; project to them and
the output goes to the mapped Ether Dream DAC(s).

## Status & caveats (please read)

The Ether Dream side, the frame decode, and the conversion are built on well-verified ground (the
decode is regression-tested against real captures in `../tests/decrypt_pcaps.py`). The **FB4
device emulation is the part that needs real-hardware iteration**:

- The handshake/config replies are replayed from real FB4 captures with the serial and challenge
  response (`B`) patched per session. QuickShow/BEYOND may check per-session fields we currently
  replay verbatim (reply sequence counters, the device clock in `0181`, status cadence). If it
  connects but won't project, those are the first things to tune — capture the exchange and diff
  against a real FB4 session.
- Discovery: the emulator periodically broadcasts the FB4E announcement. Depending on how
  QuickShow/BEYOND drives discovery, it may also need to reply to the host's query directly.
- Timing: scan-out acks (`0d8a`) are emitted on a fixed cadence; the real device ties these to the
  scan clock.
- This has been written but not yet validated against live QuickShow/BEYOND + Ether Dream
  hardware. Treat the first run as bring-up; capture traffic on both sides to debug.

## Layout

- `src/main.rs` — discover DACs; bridge each to an emulated FB4.
- `src/fb4_device.rs` — FB4 emulation (announce, TCP handshake/config, frame decrypt, UDP turbo).
- `src/etherdream.rs` — drive one DAC from the shared point buffer.
- `src/convert.rs` — FB4 point → Ether Dream point.
- `assets/fb4_device_templates.json` — captured FB4 device replies (announce, `0181`, acks, status).
