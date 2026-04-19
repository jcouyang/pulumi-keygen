{pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/1766437c5509.tar.gz") {}}:
with builtins;

let pulumi = pkgs.pulumi-bin.overrideDerivation (o: {
      srcs = builtins.filter (a: !isNull (builtins.match "pulumi(-resource-aws)*-v.*" a.name)) o.srcs;
    });
    version = "0.1";
in pkgs.mkShell {
  buildInputs = [
    pkgs.gopls
    pkgs.go
    pulumi ] ++ pkgs.lib.optionals (pkgs.stdenv.isLinux) [
    # CGO dependencies for PKCS#11 support
    pkgs.gcc
    pkgs.pkg-config
    pkgs.openssl
    pkgs.softhsm
    pkgs.opensc
  ] ;

  # Set CGO_ENABLED for PKCS#11 support
  CGO_ENABLED = if pkgs.stdenv.isLinux then "1" else "0";
  HSM_LIB = if pkgs.stdenv.isLinux then "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so" else "";

  shellHook = ''
    export VERSION=${version}.''${GITHUB_RUN_NUMBER:-local}
  '';
}
