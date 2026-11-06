class WdAutoUnlock < Formula
  desc "Western Digital My Passport auto-unlock and auto-mount utility"
  homepage "https://github.com/bobinx/wdpassport-auto-unlock"
  url "https://github.com/bobinx/wdpassport-auto-unlock/archive/refs/tags/1.0.tar.gz"
  version "1.0.0"
  license "MIT"

  depends_on "go" => :build
  depends_on :linux

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w"), "./cmd/wd-auto-unlock"
    etc.install "wdpassport.conf.example" => "wdpassport.conf.example"
    pkgshare.install "wd-unlock.service", "wd-unlock.timer", "99-wd-passport.rules"
  end

  def caveats
    <<~EOS
      To enable systemd hotplug and boot service on Linux:
        sudo cp #{pkgshare}/wd-unlock.service /etc/systemd/system/
        sudo cp #{pkgshare}/wd-unlock.timer /etc/systemd/system/
        sudo cp #{pkgshare}/99-wd-passport.rules /etc/udev/rules.d/
        sudo systemctl enable --now wd-unlock.timer
        sudo udevadm control --reload-rules

      Run the interactive setup wizard:
        sudo #{bin}/wd-auto-unlock config
    EOS
  end

  test do
    assert_match "wd-auto-unlock 1.0.0", shell_output("#{bin}/wd-auto-unlock --version")
  end
end
