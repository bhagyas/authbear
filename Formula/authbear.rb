class Authbear < Formula
  desc "CLI auth broker with keychain-backed credentials"
  homepage "https://github.com/bhagyas/authbear"
  url "https://github.com/bhagyas/authbear/releases/download/v0.1.0/authbear_0.1.0_src.tar.gz"
  sha256 "531c12d4cefd4f241379518f30338e71ed81f7514cbe1cc3cb33260167f22e25"
  license "NOASSERTION"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w"), "./cmd/authbear"
  end

  test do
    output = shell_output("#{bin}/authbear --help")
    assert_match "authbear", output
  end
end
