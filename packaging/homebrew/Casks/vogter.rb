cask "vogter" do
  version "0.1.0"
  # PLACEHOLDER: replace after the v0.1.0 release is published (scripts/release.sh --shas v0.1.0)
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  url "https://github.com/schlunsen/vogter/releases/download/v#{version}/Vogter-#{version}-macos-arm64.zip"
  name "Vogter"
  desc "Menu bar app that watches for malware, keyloggers and spying"
  homepage "https://github.com/schlunsen/vogter"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on arch: :arm64
  # The app is a front end for the vogterd service, which the formula provides
  # (`brew services start vogter`).
  depends_on formula: "schlunsen/vogter/vogter"
  depends_on macos: :sonoma

  app "Vogter.app"

  uninstall quit: "com.vogter.app"

  zap trash: [
    "~/Library/Application Support/Vogter",
    "~/Library/Preferences/com.vogter.app.plist",
  ]

  caveats <<~EOS
    Vogter.app is ad-hoc signed and not notarized by Apple yet, so Gatekeeper
    blocks the first launch ("Apple could not verify..."). Either:
      * open it once, then allow it in System Settings > Privacy & Security >
        "Open Anyway" (on macOS 14 a right-click > Open also works), or
      * remove the quarantine flag yourself, after checking you trust the download:
          xattr -dr com.apple.quarantine /Applications/Vogter.app
    (Homebrew's old --no-quarantine install flag has been removed, and it did the
    same thing without asking.)

    The app needs the service running:
      brew services start vogter
  EOS
end
