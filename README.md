# Vogter

A native macOS app that watches your Mac for malware, keyloggers, spying and
use you didn't intend. Rust backend, SwiftUI front end.

## Status: phase 2: background service and menu bar app

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
  vogter-store    SQLite history: active/new/resolved findings, acknowledgements, event log
  vogter-ipc      daemon <-> client protocol (newline-delimited JSON over a Unix socket)
  vogterd         the service: timed scans, mic/camera watch, socket server with peer checks
  vogter-cli      the `vogter` binary: one-shot scans and a client for vogterd
app/              SwiftUI menu bar app (SwiftPM; `swift test` checks protocol decoding)
packaging/        LaunchDaemon plist
scripts/          build-app.sh, install-daemon.sh
```

Socket security: only root, the service's own user, or the user at the console may connect.
When the service is signed with a Developer ID, peers must also be signed by the same team
(checked by audit token, not PID).

Planned: `vogter-es` (Endpoint Security client).

## Roadmap

1. **Scanner** (done): one-shot `vogter scan`.
2. **Service and app** (done): timed scans with history, change alerts, mic/camera alerts
   (mic names the app; camera doesn't yet), menu bar app.
3. **Endpoint Security** (realtime): program launches with signing info, reads of sensitive
   files (Keychain, browser cookies and logins, `~/.ssh`, Messages), new background/login items,
   permission changes, logins, screen sharing, `sudo`, lock/unlock ("what happened while I was
   away"). Needs Apple's `com.apple.developer.endpoint-security.client` entitlement; until it's
   granted, develop in a macOS VM with SIP disabled.
4. **Detection quality**: allowlists, learning what's normal for this Mac, Sigma rules via
   `rsigma-eval`, YARA scanning of new binaries via `yara-x`.
5. **Later**: Network Extension (Swift) for per-app network control, notarized releases.

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
