class Vogter < Formula
  desc "Watches your Mac for malware, keyloggers and spying"
  homepage "https://github.com/schlunsen/vogter"
  url "https://github.com/schlunsen/vogter/archive/refs/tags/v0.1.0.tar.gz"
  # PLACEHOLDER: replace after tagging v0.1.0 (scripts/release.sh --shas v0.1.0)
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "Apache-2.0"
  head "https://github.com/schlunsen/vogter.git", branch: "main"

  depends_on "rust" => :build
  depends_on :macos

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/vogter-cli")
    system "cargo", "install", *std_cargo_args(path: "crates/vogterd")
  end

  service do
    run opt_bin/"vogterd"
    keep_alive true
    log_path var/"log/vogterd.log"
    error_log_path var/"log/vogterd.log"
  end

  def caveats
    <<~EOS
      Start the service as your user (scans every 5 minutes, watches live):
        brew services start vogter
      Then ask it what it found:
        vogter status

      Give vogterd Full Disk Access so it can read the privacy-permission (TCC)
      databases: System Settings > Privacy & Security > Full Disk Access, add
        #{opt_bin}/vogterd
      (the path stays the same across upgrades). The one-shot `vogter scan` needs
      the same for your terminal app.

      The menu bar app is a separate cask:
        brew install --cask schlunsen/vogter/vogter

      Running as your user does not see other users' or root's processes, and
      Endpoint Security (Keychain/cookie/SSH-key reads) needs root. For that, use
      the root LaunchDaemon instead of `brew services`: install the app to
      /Applications and run scripts/install-daemon.sh from the Vogter repository:
        https://github.com/schlunsen/vogter#readme
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/vogter --version")
    assert_match version.to_s, shell_output("#{bin}/vogterd --version")
  end
end
