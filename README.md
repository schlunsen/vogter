<div align="center">

<img src="docs/images/icon.png" width="128" height="128" alt="Vogter icon">

# Vogter

**A watchful guard for your Mac.** It spots keyloggers, sneaky startup items,
info-stealers and anyone using your Mac while you're away.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
<!-- CI badge: the workflow lands with the release automation. -->
![CI](https://github.com/schlunsen/vogter/actions/workflows/ci.yml/badge.svg)
![macOS 14+](https://img.shields.io/badge/macOS-14%2B-lightgrey.svg)

</div>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/hero-dark.png">
  <img src="docs/images/hero-light.png" alt="Vogter's main window showing an alert about a fake password dialog, with the menu bar popover listing recent alerts and findings">
</picture>

Vogter lives in your menu bar. The shield turns orange or red when something needs a look,
and a mic or camera icon appears while either is in use. You get a notification when
something new and important happens, with a plain-language explanation of what it means and
what to do about it. Everything runs on your Mac, and nothing is sent anywhere.

> The screenshots are generated from made-up demo data (`scripts/screenshots.sh`).

## What it watches

<table>
  <tr>
    <td width="33%"><img src="docs/images/keystrokes.jpg" alt=""></td>
    <td width="33%"><img src="docs/images/persistence.jpg" alt=""></td>
    <td width="33%"><img src="docs/images/away.jpg" alt=""></td>
  </tr>
  <tr>
    <td align="center">Who can read your keystrokes</td>
    <td align="center">What starts with your Mac</td>
    <td align="center">What happened while you were away</td>
  </tr>
</table>

- **Keyloggers.** Any program that listens to your keyboard, and apps you've given *Input
  Monitoring* or *Accessibility* permission. A signed, notarized keyboard tool is flagged
  lightly; an unsigned one, or one running from a Downloads or temp folder, loudly.
- **Privacy permissions.** Which apps may record your screen, read all your files, or use your
  camera or microphone, and whether those apps are properly signed.
- **Startup items.** Things that launch at login or boot: scripts, unsigned programs, and items
  pretending to be Apple's.
- **Suspicious programs, the moment they start.** Fake password dialogs (the way info-stealers
  like AMOS get your password), Keychain dumping, `curl … | sh`, hidden encoded commands,
  turning Gatekeeper off, removing the "downloaded from the internet" flag, new user accounts,
  scripts typing into other apps, unsigned programs in temp or Downloads folders.
- **Microphone and camera.** A notification as soon as either turns on, with the name of the
  app using the microphone.
- **Someone at your Mac.** Every `sudo` (and failed password attempts), screen lock and unlock,
  and a **"While you were away"** summary when you unlock: *"While you were away (2h 10m): 1
  alert, 3 programs started"*.
- **macOS protections.** System Integrity Protection, Gatekeeper, FileVault and the firewall
  being off. **Remote Login (SSH)** or **Screen Sharing** switched on. Programs accepting
  connections from the network.

With Apple's Endpoint Security (see [below](#first-run)), Vogter also sees programs reading
your Keychain, browser passwords and cookies, SSH keys and Messages, plus SSH logins,
screen-sharing sessions and XProtect malware detections.

## What you can do with an alert

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/activity-dark.png">
  <img src="docs/images/activity-light.png" alt="The Activity tab with the details of a critical alert: what this means, the program, its signature and location, the command line, and Trust, Show in Finder, Copy details and Quit program buttons">
</picture>

Click an alert in the menu, or the notification, and the main window opens on it:

- **What this means**: why this is worth a look, and when it's fine.
- **Program**: what ran, whether it's still running, who signed it, where it lives, the exact
  command and what started it.
- **Trust…**: "I know this app, stop telling me." Choose this kind of alert, or all alerts.
- **Show in Finder**, **Copy details**, and **Quit program…** (asks it to quit, like Activity
  Monitor) while it's still running.

On the **Findings** tab (things that are *currently* true, like a keyboard tap or a startup
item), the check mark means "I know about this one" and hides it until it goes away and comes back.

**Trust is hard to fake.** A signed app is trusted by its developer's Apple ID, which a lookalike
can't copy. An unsigned file is trusted by its exact contents, so if it's swapped for something
else, trust ends. Apple's own tools (like `bash`) are only ever trusted for one specific alert,
since they can run anything. The **Trusted** tab lists your rules and lets you remove them.

**Vogter learns what's normal.** For the first week it quietly learns which programs you use.
After that, a program running for the first time is noted. Programs you use all the time (20+
runs over 3+ days) get their low and medium launch alerts toned down one level. High and
critical alerts are never toned down.

<table>
  <tr>
    <td><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/findings-dark.png"><img src="docs/images/findings-light.png" alt="Findings tab: a keyboard tap, a startup item running a script, and the firewall being off"></picture></td>
    <td><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/status-dark.png"><img src="docs/images/status-light.png" alt="Status tab: service version, scan interval, realtime sources and Endpoint Security state"></picture></td>
  </tr>
  <tr>
    <td align="center">Findings</td>
    <td align="center">Status</td>
  </tr>
</table>

## Install

### Homebrew (coming with the first release, v0.1.0)

```sh
brew install --cask schlunsen/vogter/vogter   # the menu bar app
brew install schlunsen/vogter/vogter          # the command-line tools
```

See [docs/homebrew.md](docs/homebrew.md) for details.

### Build from source

You need macOS 14 or later, [Rust](https://rustup.rs) 1.88+ (edition 2024) and Xcode 16+
(Swift 6 tools).

```sh
git clone https://github.com/schlunsen/vogter.git && cd vogter
scripts/build-app.sh                      # builds build/Vogter.app (with vogterd and vogter inside)
cp -R build/Vogter.app /Applications/
```

## First run

Vogter has two parts: a background **service** (`vogterd`) that does the watching, and the
**menu bar app** that shows you what it found. The app connects to the service automatically.

1. **Start the service.** The recommended way is as root at boot, so it can see every process:

   ```sh
   sudo scripts/install-daemon.sh            # after copying Vogter.app to /Applications
   ```

   Or just for yourself, without root (it sees only your own programs):

   ```sh
   /Applications/Vogter.app/Contents/Helpers/vogterd     # or: cargo run --release -p vogterd
   ```

2. **Grant Full Disk Access**, so Vogter can read which apps have privacy permissions:
   **System Settings → Privacy & Security → Full Disk Access**, click **+**, press
   <kbd>⌘</kbd><kbd>⇧</kbd><kbd>G</kbd> and enter
   `/Applications/Vogter.app/Contents/Helpers/vogterd`. If you run the service from a
   terminal, add the terminal app instead. Restart the service afterwards
   (`sudo scripts/install-daemon.sh` again).

3. **Open Vogter** and **allow notifications** when asked.

The first scan is a baseline: what's already on your Mac is listed but doesn't alert you.
After that, only *changes* do. To remove the service: `sudo scripts/install-daemon.sh uninstall`.

**Endpoint Security**, Apple's kernel event feed, gives Vogter its sharpest view (every program
launch, reads of secret files, logins). It needs a special entitlement from Apple, which this
project doesn't have yet, so Vogter currently uses its fallback watchers. The Status tab says
which are active. See [docs/endpoint-security.md](docs/endpoint-security.md).

## Command line

`vogter` talks to the running service, except `scan` and `inventory`, which work on their own.

| Command | What it does |
| --- | --- |
| `vogter scan [-s info\|low\|medium\|high\|critical] [--json]` | One-shot scan and report, no service needed (`sudo` also sees root processes) |
| `vogter status` | Last scan, open findings, mic/camera, realtime sources |
| `vogter findings [--all]` | Open findings with their keys (`--all` includes acknowledged ones) |
| `vogter events [-n 30]` | Recent activity with ids |
| `vogter show <id>` | Everything known about one event |
| `vogter trust <key>` / `vogter trust --event <id> [--all-checks]` | Trust what a finding or event is about |
| `vogter trusted` | List trust rules |
| `vogter untrust <id>` | Remove a trust rule |
| `vogter ack <key>` | Hide a finding until it goes away and comes back |
| `vogter watch` | Live event stream |
| `vogter scan-now` | Ask the service to scan right away |
| `vogter inventory [processes\|taps\|tcc\|launchd\|cron\|listeners\|health]` | Raw sensor data as JSON |

## Privacy

- **Everything stays on your Mac.** History is a SQLite database in
  `~/Library/Application Support/Vogter/` (or `/Library/Application Support/Vogter/` when the
  service runs as root). Vogter makes no network connections: no telemetry, no cloud lookups,
  no updates phoning home.
- **Secrets are scrubbed.** Passwords, tokens and API keys in command lines (`--password=…`,
  `Authorization:` headers, `https://user:pass@…`, GitHub/AWS/Slack-style tokens) are replaced
  with `[redacted]` before anything is stored or shown.
- Only you (the user at the console) and root can talk to the service.

## Limitations

- **Without Endpoint Security, very short-lived programs can be missed.** The fallback watcher
  checks for new programs every second, so something that starts and exits faster than that may
  not be seen. Reads of secret files and SSH logins aren't seen at all without it.
- **The camera alert can't say which app** is using it (the microphone alert can).
- **Endpoint Security needs Apple's entitlement**, which takes a request to Apple and a paid
  developer account. Until then, see [docs/endpoint-security.md](docs/endpoint-security.md) for
  testing in a VM.
- **It's not an antivirus.** Vogter doesn't scan files for known malware. It watches for
  *behaviour* (spying, persistence, tampering). Keep macOS's built-in XProtect and Gatekeeper
  on; Vogter tells you if they're off.
- Early software (v0.1.0). Expect rough edges, and please [open an issue](https://github.com/schlunsen/vogter/issues).

## For developers

Rust does the work and SwiftUI shows it:

```
crates/vogter-model    shared types and secret redaction
crates/vogter-sensors  gathers facts: signatures, event taps, TCC, processes, sockets, startup items, health, mic/camera
crates/vogter-detect   the rules: facts -> findings, program launches -> alerts, trust (pure, unit-tested)
crates/vogter-es       Endpoint Security client
crates/vogter-store    SQLite history
crates/vogter-ipc      daemon <-> client protocol (JSON lines over a Unix socket)
crates/vogterd         the service
crates/vogter-cli      the `vogter` command
app/                   SwiftUI menu bar app (SwiftPM)
```

```sh
cargo test                        # Rust: rules, store, protocol, redaction
swift test --package-path app     # Swift: protocol decoding against captured daemon output
cargo run --release -p vogterd    # run the service as your user
scripts/screenshots.sh            # regenerate docs/images from demo data
```

How the checks, realtime watchers, trust and learning work in detail, the socket security
model, and why Vogter isn't built on Rustinel: [docs/design.md](docs/design.md).

### Roadmap

1. **Scanner** (done): one-shot `vogter scan`.
2. **Service and app** (done): timed scans with history, change alerts, mic/camera alerts, menu bar app.
3. **Realtime** (done): live program checks, startup and permission folder watching, sudo,
   lock/unlock with an away summary. The Endpoint Security client is built and waits for Apple's entitlement.
4. **Trust and learning** (done).
5. **More detection**: Sigma rules via `rsigma-eval`, YARA scanning of new binaries via `yara-x`.
6. **Later**: Network Extension for per-app network control, notarized releases.

Ideas from [Objective-See](https://github.com/objective-see)'s tools (ideas only; they're GPL),
[Santa](https://github.com/northpolesec/santa) and [Mac Monitor](https://github.com/Brandon7CC/mac-monitor).

## License

[Apache-2.0](LICENSE)
