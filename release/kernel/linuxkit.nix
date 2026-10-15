# linuxkit, which nitro-cli runs to build the EIF's ramdisks: exactly
# AWS's linuxkit/linuxkit.nix (version, source hash, patches in aws/linuxkit).
{ pkgs }:
pkgs.buildGoModule rec {
  pname = "linuxkit";
  version = "1.5.2";

  src = pkgs.fetchFromGitHub {
    owner = "linuxkit";
    repo = "linuxkit";
    rev = "v${version}";
    sha256 = "sha256-M/M4m/vsvvtSDnNNy8p6x+xpv1QmVzyfPRf/BNBX7zA=";
  };

  nativeCheckInputs = with pkgs.buildPackages; [
    git
  ];

  vendorHash = null;

  modRoot = "./src/cmd/linuxkit";

  ldflags = [
    "-s"
    "-w"
    "-X github.com/linuxkit/linuxkit/src/cmd/linuxkit/version.Version=${version}+"
    "-linkmode external"
    "--buildmode pie"
  ];

  patches = [
    ./aws/linuxkit/0001-build-Allow-to-ad-a-directory-prefix-when-unpacking-.patch
    ./aws/linuxkit/0002-output-Add-new-type-kernel-initrd-nogz.patch
    ./aws/linuxkit/0003-Fix-output-image-duplicate-entries.patch
  ];
}
