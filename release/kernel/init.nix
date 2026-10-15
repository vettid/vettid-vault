# init: AWS's init.c (aws/init, unchanged) with patches/init-builtin-nsm.patch,
# built statically as AWS's init/init.nix does.
{ pkgs }:
pkgs.stdenv.mkDerivation {
  name = "vettid-enclave-init";

  src = ./aws/init;

  patches = [ ./patches/init-builtin-nsm.patch ];

  buildPhase = ''
    $CC -Wall -Wextra -Werror -O2 -o init init.c -flto
    $STRIP --strip-all init
  '';

  installPhase = ''
    mkdir -p $out
    cp init $out/
  '';
}
