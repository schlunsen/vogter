# Vogter

A native macOS app that watches your Mac for malware, keyloggers, spying and
use you didn't intend. Rust backend, SwiftUI front end.

## Status: phase 1 — on-demand scanner

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
  vogter-model    shared types: Snapshot (raw facts) and Finding (assessed result)
  vogter-sensors  gathers facts: codesign, eventtap, tcc, process, network, persistence, health
  vogter-detect   rules: Snapshot -> Vec<Finding>, pure and unit-tested
  vogter-cli      the `vogter` binary
```

Planned additions: `vogter-es` (Endpoint Security client), `vogter-store`
(SQLite history), `vogter-ipc` (daemon ↔ app), `vogterd` (root LaunchDaemon),
`app/` (SwiftUI menu bar app), `packaging/`.

## Roadmap

1. **Scanner** (done): one-shot `vogter scan`.
2. **Daemon and app**: `vogterd` runs scans on a schedule, stores them in SQLite and alerts on
   *changes* (new tap, new permission grant, new launch item). The SwiftUI menu bar app shows them,
   talking to the daemon over a Unix socket that checks the caller's code signature. Live
   mic/camera-in-use alerts.
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
