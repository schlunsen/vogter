cask "vogter" do
  version "0.1.0"
  sha256 "235fa4c133fc127423579397e606f05dff9f95f3c96b8b74da5bc3091b98998f"

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
    Vogter.app is signed with a Developer ID and notarized by Apple.

    The app needs the service running:
      brew services start vogter
  EOS
end
