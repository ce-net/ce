# Homebrew formula for CE.
# Install via:   brew install ce-net/ce/ce
# Or tap first:  brew tap ce-net/ce && brew install ce
#
# SHA256 values must be updated after each release.
# Run: packaging/scripts/update-homebrew-sha256.sh <version>
class Ce < Formula
  desc "Peer-to-peer compute mesh and economy"
  homepage "https://github.com/ce-net/ce"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ce-net/ce/releases/download/v#{version}/ce-macos-arm64.tar.gz"
      sha256 "PLACEHOLDER_MACOS_ARM64"
    else
      url "https://github.com/ce-net/ce/releases/download/v#{version}/ce-macos-amd64.tar.gz"
      sha256 "PLACEHOLDER_MACOS_AMD64"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/ce-net/ce/releases/download/v#{version}/ce-linux-arm64.tar.gz"
      sha256 "PLACEHOLDER_LINUX_ARM64"
    else
      url "https://github.com/ce-net/ce/releases/download/v#{version}/ce-linux-amd64.tar.gz"
      sha256 "PLACEHOLDER_LINUX_AMD64"
    end
  end

  def install
    bin.install "ce"
  end

  service do
    run [opt_bin/"ce", "start"]
    keep_alive true
    log_path var/"log/ce.log"
    error_log_path var/"log/ce.log"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/ce --version")
  end
end
