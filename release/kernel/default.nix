# The enclave blob set built from source (docs/KERNEL.md). release/kernel/build.sh
# passes every argument from kernel.lock; `nix-build -A all` then gives the
# six files nitro-cli takes from its blobs directory, plus extra/.
{ nixpkgsUrl, nixpkgsSha256, kernelVersion, kernelUrl, kernelSha256, buildUser, buildHost }:
let
  pkgs = import (builtins.fetchTarball { url = nixpkgsUrl; sha256 = nixpkgsSha256; }) { };
in
assert pkgs.stdenv.hostPlatform.system == "aarch64-linux";
rec {
  # build.sh has already checked the tarball's SHA-256 and kernel.org's
  # signature, and added it to the store under this hash.
  kernelSrc = pkgs.fetchurl { url = kernelUrl; sha256 = kernelSha256; };

  kernel = import ./kernel.nix {
    inherit pkgs buildUser buildHost;
    version = kernelVersion;
    src = kernelSrc;
  };

  # The configuration step alone (KERNEL_TARGET=kernelConfig): the
  # resolved .config, checked against the fragment, in a minute or two.
  kernelConfig = kernel.overrideAttrs (_: {
    buildPhase = "true";
    installPhase = "mkdir -p $out && cp .config $out/Image.config";
    fixupPhase = "true";
  });

  # The compilers and libraries the blob set is built with; build.sh
  # checks their NAR hashes against kernel.lock's toolchain lines.
  toolchain = {
    gcc = pkgs.stdenv.cc.cc; # the kernel's compiler (GCC 13.2.0)
    binutils = pkgs.stdenv.cc.bintools.bintools; # GNU ld and friends (2.41)
    muslGcc = pkgs.pkgsStatic.stdenv.cc.cc; # init's compiler
    musl = pkgs.pkgsStatic.stdenv.cc.libc; # init's C library
    go = pkgs.pkgsStatic.buildPackages.go; # linuxkit's compiler
  };

  init = pkgs.pkgsStatic.callPackage ./init.nix { };

  linuxkit = pkgs.pkgsStatic.callPackage ./linuxkit.nix { };

  all = pkgs.runCommandNoCC "vettid-enclave-blobs-${kernelVersion}" { } ''
    mkdir -p $out/extra
    cp ${kernel}/Image ${kernel}/Image.config $out/
    cp ${kernel}/extra/* $out/extra/
    cp ${./cmdline} $out/cmdline
    cp ${init}/init $out/init
    cp ${linuxkit}/bin/linuxkit $out/linuxkit
    # NSM is built into the kernel; nitro-cli still needs an nsm.ko, and
    # the patched init removes an empty one without loading it.
    : > $out/nsm.ko
  '';
}
