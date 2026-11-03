# How Vogter works

The README covers what Vogter does for you. This page is the detail: what each check
looks at, how trust and learning work, how the pieces fit, and why it isn't built on
an existing engine.

## Periodic checks

`vogterd` takes a full snapshot of the Mac every 5 minutes (`--interval`), and right away
when a startup folder or permission database changes. The first scan is a baseline, so
only *changes* after it alert you. No special entitlement needed:

| Check | How |
| --- | --- |
| Keystroke taps (keyloggers) | `CGGetEventTapList`: who has a keyboard event tap, and whether it is listen-only |
| Input Monitoring / Accessibility / Screen Recording / Full Disk / camera / mic grants | TCC databases + code signature of each granted app (needs Full Disk Access) |
| Processes | Code signature (Apple / developer / notarized / ad-hoc / unsigned / broken), deleted executables, runs from temp / Downloads / hidden Library folders |
| Persistence | LaunchDaemons & LaunchAgents (script runners, fake `com.apple.*` labels, unsigned targets), crontab |
| Other footholds | Shell startup files (download-and-run, encoded code, background jobs, programs in temp/Downloads, password dialogs, `sudo`/`ssh` wrappers, `DYLD_INSERT_LIBRARIES`), SSH `authorized_keys`, `/etc/hosts` redirects and blocks, sudoers `NOPASSWD`/`!authenticate`, configuration profiles, login hooks, system and kernel extensions, Background Task Management items. Root only: sudoers, root's SSH keys and login hook, Mac-wide profiles, `sfltool dumpbtm` |
| Network | Sockets listening on non-loopback addresses, per process |
| System health | SIP, Gatekeeper, FileVault, firewall, XProtect version, Remote Login (SSH) and Screen Sharing switched on |

`vogter inventory [processes|taps|tcc|launchd|cron|listeners|health]` dumps the raw facts
behind these checks as JSON.

## Realtime

Between scans, `vogterd` watches live:

- **New programs** are checked at launch: fake password dialogs (`osascript … hidden answer`),
  Keychain dumping, `curl … | sh`, hidden base64 payloads, quarantine removal, Gatekeeper
  being turned off, account changes, scripts typing into other apps, unsigned programs in
  temp or Downloads folders. Each alert carries plain-language advice ("What this means").
- **Startup items** and **permission databases** trigger an immediate rescan when they change (FSEvents).
- **sudo** (successful and failed), **screen lock and unlock**, and a **"while you were away"**
  summary on unlock listing the alerts and programs that started while the screen was locked.
- **Microphone and camera**: polled every second; the microphone reports which app uses it.
- With **Endpoint Security**, also reads of your Keychain, browser cookies and passwords,
  SSH/AWS/GPG keys and Messages by programs that shouldn't touch them, new background
  items with the process that added them, SSH logins, screen-sharing sessions and XProtect
  detections. See [endpoint-security.md](endpoint-security.md) for what works with and
  without it.

`vogter status` (and the app's Status tab) shows which realtime sources are active and, if
Endpoint Security is off, why.

The same alert (kind + summary + path) is reported at most once per 10 minutes.

## Trust and learning

- **Trust** an app or file from any finding or activity (thumbs-up in the app, or
  `vogter trust <key>` / `vogter trust --event <id>`).
  - Signed apps are trusted by developer **Team ID**, which a lookalike can't fake.
  - Unsigned files are trusted by their exact **SHA-256**, so trust ends if the file is replaced.
  - Apple tools (`/bin/bash` …) are only ever trusted for **one specific alert**, because they run everything.
  - Trust covers a family of related alerts (process, startup items, permissions, keylogger,
    network), or all alerts if you choose.
  - `vogter trusted` and `vogter untrust <id>` (or the Trusted tab) manage the rules.
- **Acknowledge** (`vogter ack <key>`, the check mark in the app) hides one finding until it
  goes away and comes back.
- **Learning:** Vogter remembers every non-Apple program it sees. For the first 7 days it only
  learns. After that, a program running for the first time is noted (Low if it has no developer
  signature). Low and Medium launch alerts for programs that have run 20+ times over 3+ days
  are lowered one level. High and Critical are never lowered.

## Secrets in command lines

Command lines are stored and shown, so they are redacted first
(`crates/vogter-model/src/redact.rs`): values of `--password`/`token`/`secret`/`api-key`-style
flags, `Authorization:` headers, `user:pass@` in URLs and common token prefixes (GitHub,
Slack, AWS, …) become `[redacted]`.

## Layout

```
crates/
  vogter-model    shared types: Snapshot (raw facts), Finding, StoredFinding, Activity, AvState, redaction
  vogter-sensors  gathers facts: codesign, eventtap, tcc, process, network, persistence, health, av
  vogter-detect   rules: Snapshot -> Vec<Finding>, program launches -> Activity, trust; pure and unit-tested
  vogter-es       Endpoint Security client (two clients: process/session events, secret-file opens)
  vogter-store    SQLite history: active/new/resolved findings, acknowledgements, event log, trust, programs seen
  vogter-ipc      daemon <-> client protocol (newline-delimited JSON over a Unix socket)
  vogterd         the service: timed scans, realtime watchers, mic/camera, socket server
  vogter-cli      the `vogter` binary: one-shot scans and a client for vogterd
app/              SwiftUI menu bar app (SwiftPM; `swift test` checks protocol decoding)
packaging/        LaunchDaemon plist, Endpoint Security entitlements
scripts/          build-app.sh, install-daemon.sh, screenshots.sh
```

All decisions about what is suspicious live in `vogter-detect`; the sensors and the ES client
only gather facts.

**Socket security:** only root, the service's own user, or the user at the console may connect.
When the service is signed with a Developer ID, peers must also be signed by the same team
(checked by audit token, not PID).

**Data:** `~/Library/Application Support/Vogter/vogter.db` when run as your user,
`/Library/Application Support/Vogter/vogter.db` as root.

## Screenshots

`scripts/screenshots.sh` regenerates `docs/images/*-{light,dark}.png`. It runs the app with
`--render-screenshots <dir>`, which fills the real views with made-up data
(`app/Sources/Vogter/Demo.swift`), draws them offscreen and exits. No daemon is contacted and
nothing from your Mac appears in the images. The TabView's tab strip is redrawn because the
system's selected-tab material can't be captured offscreen. Everything inside the tabs is the
real view.

## Why not build on Rustinel?

[Rustinel](https://github.com/Karib0u/rustinel) (Rust, Apache-2.0) is a good engine but a poor
foundation here (checked at v1.11.0-rc.2):

- Its macOS support is experimental. It subscribes to only six Endpoint Security events
  (exec, exit, create, unlink, rename, close), so it doesn't see file opens, background-item
  additions, permission changes, logins, screen sharing or event taps: the signals Vogter
  cares about most.
- It is built for Windows and for feeding a central log server (about 120k lines in one
  crate), and its library API isn't meant for outside use.
- Its reusable parts are separate crates already (`endpoint-sec`, `rsigma-eval`, `yara-x`,
  `libproc`), which Vogter can use directly.

Its one real advantage is a signed `Rustinel.app` that already holds the Endpoint Security
entitlement. Its NDJSON alert file could serve as an optional extra input for realtime process
and file events before Vogter has its own entitlement.

## Prior art

Ideas from [Objective-See](https://github.com/objective-see) (ReiKey, BlockBlock, KnockKnock,
OverSight, LuLu; all GPL, so ideas only, no code), [Santa](https://github.com/northpolesec/santa),
[Mac Monitor](https://github.com/Brandon7CC/mac-monitor).
