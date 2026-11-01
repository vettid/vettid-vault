# The enclave kernel: AWS's recipe (aws-nitro-enclaves-sdk-bootstrap
# kernel/kernel.nix at aws_bootstrap_commit), with the kernel.org tarball
# instead of the GitHub mirror, NSM built in, no modules, and VettID's
# config fragment. aarch64 only; built natively.
{ pkgs, version, src, buildUser, buildHost }:
pkgs.stdenv.mkDerivation {
  pname = "vettid-enclave-kernel";
  inherit version src;

  nativeBuildInputs = with pkgs.buildPackages; [
    flex
    bison
    elfutils
    openssl
    bc
    perl
    gawk
  ];

  # The kernel's own Kconfig decides its compiler hardening; the Nix
  # compiler wrapper's flags (as for every kernel nixpkgs builds) stay out.
  hardeningDisable = [ "all" ];

  patches = [
    # NSM driver, from AWS: upstream in Linux 6.8, not in 6.6.y.
    ./aws/kernel/nsm.patch
    # virtio-vsock parent/enclave deadlock, from AWS (Alexander Graf,
    # 2024-11), rebased onto 6.6.y; not upstream as of 6.6.161.
    ./patches/0001-vsock-virtio-Remove-queued_replies-pushback-logic.patch
  ];

  configurePhase = ''
    runHook preConfigure
    cat ${./aws/kernel/microvm-kernel-config-aarch64} ${./config/hardening.config} > .config
    make ARCH=arm64 olddefconfig
    bash ${./check-config.sh} ${./config/hardening.config} .config
    runHook postConfigure
  '';

  buildPhase = ''
    runHook preBuild
    patchShebangs scripts
    # Reproducible: the time is SOURCE_DATE_EPOCH (set by Nix's unpack
    # phase to the newest file time in the kernel tarball), the
    # user, host and build number are fixed; in-tree build, so the kernel
    # records relative paths only.
    export KBUILD_BUILD_TIMESTAMP="$(date -u -d @$SOURCE_DATE_EPOCH)"
    export KBUILD_BUILD_USER=${buildUser}
    export KBUILD_BUILD_HOST=${buildHost}
    export KBUILD_BUILD_VERSION=1
    make ARCH=arm64 Image -j "$NIX_BUILD_CORES"
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/extra
    cp arch/arm64/boot/Image $out/Image
    cp .config $out/Image.config
    cp System.map vmlinux $out/extra/
    runHook postInstall
  '';

  # As AWS: the Nitro Enclaves loader on aarch64 loads the image at the
  # address its header names; write the Image header's text_offset
  # (bytes 8..15) as 2 MiB instead of 0.
  fixupPhase = ''
    printf "\x00\x00\x20\x00\x00\x00\x00\x00" | dd of=$out/Image bs=1 count=8 seek=8 conv=notrunc
  '';

  meta = {
    description = "Linux ${version} for the VettID enclave (Nitro Enclaves, aarch64)";
    license = "gpl2Only";
  };
}
