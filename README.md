# Vogter

A native macOS app that watches your Mac for malware, keyloggers, spying and
use you didn't intend. Rust backend, SwiftUI front end.

## Status: phase 4: trust and learning

```sh
cargo run --release -p vogterd          # the service, as your user (dev mode)
scripts/build-app.sh && open build/Vogter.app   # the menu bar app
```

The menu bar shield turns orange or red when something needs attention; a mic or camera icon
appears next to it while either is in use. You get a notification for new medium-or-higher
findings and whenever the mic or camera turns on. The first scan is a baseline, so only
*changes* after that alert you.

From the terminal (talks to the running service):

```sh
vogter status        # last scan, open findings, mic/camera now
vogter findings      # open findings with their keys
vogter ack <key>     # "I know about this one", hide it until it goes away and comes back
vogter watch         # live event stream
vogter scan-now
```

To run the service as root at boot (sees every process), copy `build/Vogter.app` to
`/Applications`, run `sudo scripts/install-daemon.sh`, and give
`/Applications/Vogter.app/Contents/Helpers/vogterd` Full Disk Access.

### Realtime

`vogterd` also watches live, not just every 5 minutes:

- **New programs** are checked at launch: fake password dialogs (`osascript … hidden answer`),
  Keychain dumping, `curl … | sh`, hidden base64 payloads, quarantine removal, Gatekeeper
  being turned off, account changes, unsigned programs in temp or Downloads folders.
- **Startup items** and **permission databases** trigger an immediate rescan when they change.
- **sudo**, **screen lock and unlock**, and a **"while you were away"** summary on unlock.
- **Remote Login / Screen Sharing** being switched on shows up as a finding.
- With **Endpoint Security**, also reads of your Keychain, browser cookies and passwords, SSH/AWS/GPG
  keys and Messages by programs that shouldn't touch them, plus SSH logins, screen-sharing
  sessions and XProtect detections. See [docs/endpoint-security.md](docs/endpoint-security.md).

`vogter status` shows which realtime sources are active and, if Endpoint Security is off, why.

### Trust and learning

- **Trust** an app or file from any finding or activity (thumbs-up in the app, or
  `vogter trust <key>` / `vogter trust --event <id>`). Signed apps are trusted by developer
  Team ID, which a lookalike can't fake. Unsigned files are trusted by their exact SHA-256, so
  trust ends if the file is replaced. Apple tools (`/bin/bash` …) are only ever trusted for one
  specific alert, because they run everything. Trust covers a family of related alerts
  (process, startup items, permissions, keylogger, network), or all alerts if you choose.
  `vogter trusted` and `vogter untrust <id>` manage the rules.
- **Learning:** Vogter remembers every non-Apple program it sees. For the first 7 days it only
  learns. After that, a program running for the first time is noted (Low if it has no developer
  signature). Low and Medium launch alerts for programs that have run 20+ times over 3+ days
  are lowered one level. High and Critical are never lowered.

### One-shot scanner

```sh
cargo build --release
./target/release/vogter scan              # findings, low severity and up
./target/release/vogter scan -s info      # everything, including the benign
./target/release/vogter scan --json
./target/release/vogter inventory taps    # raw sensor data: processes|taps|tcc|launchd|cron|listeners|health
sudo ./target/release/vogter scan         # also sees root processes and their sockets
```

Give your terminal **Full Disk Access** (System Settings → Privacy & Security)
so the privacy-permission (TCC) databases can be read.

What it checks today, no special entitlement needed:

| Check | How |
| --- | --- |
| Keystroke taps (keyloggers) | `CGGetEventTapList`: who has a keyboard event tap, and whether it is listen-only |
| Input Monitoring / Accessibility / Screen Recording / Full Disk / camera / mic grants | TCC databases + code signature of each granted app |
| Processes | Code signature (Apple / developer / notarized / ad-hoc / unsigned / broken), deleted executables, runs from temp / Downloads / hidden Library folders |
| Persistence | LaunchDaemons & LaunchAgents (script runners, fake `com.apple.*` labels, unsigned targets), crontab |
| Network | Sockets listening on non-loopback addresses, per process |
| System health | SIP, Gatekeeper, FileVault, firewall, XProtect version |

## Layout

```
crates/
  vogter-model    shared types: Snapshot (raw facts), Finding, StoredFinding, AvState
  vogter-sensors  gathers facts: codesign, eventtap, tcc, process, network, persistence, health, av
  vogter-detect   rules: Snapshot -> Vec<Finding>, pure and unit-tested
  vogter-es       Endpoint Security client (two clients: process/session events, secret-file opens)
  vogter-store    SQLite history: active/new/resolved findings, acknowledgements, event log
  vogter-ipc      daemon <-> client protocol (newline-delimited JSON over a Unix socket)
  vogterd         the service: timed scans, realtime watchers, mic/camera, socket server
  vogter-cli      the `vogter` binary: one-shot scans and a client for vogterd
app/              SwiftUI menu bar app (SwiftPM; `swift test` checks protocol decoding)
packaging/        LaunchDaemon plist
scripts/          build-app.sh, install-daemon.sh
```

Socket security: only root, the service's own user, or the user at the console may connect.
When the service is signed with a Developer ID, peers must also be signed by the same team
(checked by audit token, not PID).


## Roadmap

1. **Scanner** (done): one-shot `vogter scan`.
2. **Service and app** (done): timed scans with history, change alerts, mic/camera alerts
   (mic names the app; camera doesn't yet), menu bar app.
3. **Realtime** (done): live program checks, startup and permission folder watching, sudo,
   lock/unlock with an away summary. The Endpoint Security client is built. Testing it on a real Mac
   needs Apple's entitlement, or a VM with SIP off (see docs/endpoint-security.md).
4. **Trust and learning** (done): see above.
5. **More detection**: Sigma rules via `rsigma-eval`, YARA scanning of new binaries via `yara-x`.
6. **Later**: Network Extension (Swift) for per-app network control, notarized releases.

## Why not build on Rustinel?

[Rustinel](https://github.com/Karib0u/rustinel) (Rust, Apache-2.0) is a good engine, but it is a poor
foundation for this project (checked at v1.11.0-rc.2):

- Its macOS support is labelled experimental. It subscribes to only six Endpoint Security events
  (exec, exit, create, unlink, rename, close). It doesn't see file opens, background-item
  additions, permission changes, logins, screen sharing or event taps, which are the signals
  Vogter cares about most.
- It is built for Windows and for feeding a central log server, about 120k lines in a single
  crate. Its library API isn't meant for outside use.
- Its reusable parts are separate crates already: `endpoint-sec`, `rsigma-eval`, `yara-x` and
  `libproc`. Vogter uses those directly.

It does have one real advantage: its releases ship a signed `Rustinel.app` that already holds the
Endpoint Security entitlement. Its NDJSON alert file can serve as an optional extra input for
realtime process and file events before Vogter has its own entitlement.

## Prior art

Ideas from [Objective-See](https://github.com/objective-see) (ReiKey, BlockBlock, KnockKnock,
OverSight, LuLu; all GPL, so ideas only, no code), [Santa](https://github.com/northpolesec/santa),
[Mac Monitor](https://github.com/Brandon7CC/mac-monitor).
