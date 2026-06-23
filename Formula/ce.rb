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
      sha256 "fc518794fbcbc9b202ea8644589705a604cbcf3c85d1954e880bc2670b0508da"
    else
      odie "ce ships no Intel-Mac binary. Build from source (cargo build --release) or run: curl -sSL https://ce-net.com/install.sh | bash"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/ce-net/ce/releases/download/v#{version}/ce-linux-arm64.tar.gz"
      sha256 "d02e7f089e909bb4694b843dc3e293501e6116230e67e15902ee560afaad0b42"
    else
      url "https://github.com/ce-net/ce/releases/download/v#{version}/ce-linux-amd64.tar.gz"
      sha256 "7611ebefde6ec1f2935f90ddd2661cbb0f58b63247a8ff268a1572790f302b46"
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
