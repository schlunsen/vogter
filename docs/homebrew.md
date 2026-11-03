# Homebrew

Vogter is installed from its own tap, [schlunsen/homebrew-vogter](https://github.com/schlunsen/homebrew-vogter).
homebrew-core only takes well-known projects with a stable release history, so `brew install vogter`
without the tap prefix isn't possible yet.

The tap has:

| | What | Built from |
| --- | --- | --- |
| `Formula/vogter.rb` | `vogter` CLI and `vogterd` service | the tag's source tarball, compiled with Rust on your Mac |
| `Casks/vogter.rb` | `Vogter.app` menu bar app (Apple silicon, macOS 14+) | the release's `Vogter-<version>-macos-arm64.zip` |

Copies of both live in [`packaging/homebrew/`](../packaging/homebrew/) in this repository. The
tap is what users get; keep the two in sync.

## Installing

```sh
brew install schlunsen/vogter/vogter          # CLI + service (builds from source, needs a few minutes)
brew services start vogter                    # run vogterd as your user, now and at every login
brew install --cask schlunsen/vogter/vogter   # menu bar app; also installs the formula
```

After `brew tap schlunsen/vogter` you can use the short names (`brew install vogter`,
`brew install --cask vogter`).

Then:

- **Full Disk Access**: add `$(brew --prefix)/opt/vogter/bin/vogterd` under System Settings >
  Privacy & Security > Full Disk Access so it can read the permission (TCC) databases. The `opt`
  path stays the same across upgrades, but macOS may ask again after an upgrade because the
  binary changed.
- **Gatekeeper**: the app is ad-hoc signed and not notarized yet, so the first launch is
  blocked. Allow it under System Settings > Privacy & Security > "Open Anyway" (on macOS 14,
  right-click > Open also works), or, if you trust the download, run
  `xattr -dr com.apple.quarantine /Applications/Vogter.app`. Homebrew's old `--no-quarantine`
  flag did the same thing without asking and has been removed.
- **Logs**: `$(brew --prefix)/var/log/vogterd.log`.

`brew services` runs vogterd as your user. It doesn't see root's or other users' processes, and
Endpoint Security needs root. For the full root service, use the LaunchDaemon instead (don't run
both):

```sh
brew services stop vogter
# Vogter.app must be in /Applications (the cask puts it there)
sudo scripts/install-daemon.sh      # from a checkout of this repository
```

The installer copies `vogterd` to `/Library/PrivilegedHelperTools/com.vogter.vogterd`
(root-owned) after checking its signature. Give that path Full Disk Access.

Uninstall: `brew services stop vogter`, `brew uninstall --cask vogter`, `brew uninstall vogter`.
`brew uninstall --zap --cask vogter` also deletes `~/Library/Application Support/Vogter`
(history database and trust rules).

## Cutting a release (maintainers)

1. **Bump the version** in `Cargo.toml` (`[workspace.package] version`) and in
   `app/Info.plist` (`CFBundleShortVersionString`, and increase `CFBundleVersion`). Commit
   to `main`.

2. **Optional dry run**: Actions > Release > "Run workflow" on any branch builds everything and
   attaches the files to the run as an artifact, without publishing. Or locally:

   ```sh
   scripts/release.sh          # writes build/dist/{vogter-*.tar.gz, Vogter-*.zip, SHA256SUMS}
   ```

3. **Tag and push**:

   ```sh
   git tag -a v0.1.0 -m "Vogter 0.1.0"
   git push origin v0.1.0
   ```

   The Release workflow checks that the tag matches `Cargo.toml`, builds on macOS arm64, and
   publishes a GitHub Release with:

   - `vogter-<version>-macos-arm64.tar.gz`: `vogter`, `vogterd`, README, LICENSE
   - `Vogter-<version>-macos-arm64.zip`: `Vogter.app`
   - `SHA256SUMS`

   The workflow summary also prints the Homebrew sha256 values.

4. **Get the checksums** (after the release is published):

   ```sh
   scripts/release.sh --shas v0.1.0
   ```

   This downloads the tag's source tarball (for the formula) and the release zip (for the cask)
   from GitHub and prints their sha256 values. The source tarball's checksum isn't in
   `SHA256SUMS` because GitHub generates that file itself.

5. **Bump the tap**:

   ```sh
   git clone https://github.com/schlunsen/homebrew-vogter && cd homebrew-vogter
   # Formula/vogter.rb: url .../refs/tags/v0.1.0.tar.gz and its sha256
   # Casks/vogter.rb:   version "0.1.0" and the zip's sha256
   git commit -am "vogter 0.1.0" && git push
   ```

   For the first release, also remove the `# PLACEHOLDER` comments. The tap's CI runs `brew style`
   and `brew audit --strict`. Once the checksums are real, it also runs `--new --online` audits,
   builds the formula from source and runs its test. Copy the updated files back to
   `packaging/homebrew/` here.

   Later releases can use `brew bump-formula-pr --url <tarball-url> schlunsen/vogter/vogter`
   and `brew bump-cask-pr --version <version> schlunsen/vogter/vogter`, which compute the
   checksums themselves.

6. **Check it locally**:

   ```sh
   brew update
   brew install --build-from-source schlunsen/vogter/vogter && brew test vogter
   brew install --cask schlunsen/vogter/vogter
   ```

### Not covered yet

- **Intel Macs** get no prebuilt binaries or app. The formula still builds from source on Intel,
  but the cask is `arm64` only.
- **Notarization**: once there is a Developer ID, set `SIGN_IDENTITY` for `scripts/build-app.sh`
  in the Release workflow (the certificate goes in repository secrets), notarize the zip with
  `xcrun notarytool`, and drop the Gatekeeper caveat from the cask.
