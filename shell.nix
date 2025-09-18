{pkgs ? import <nixpkgs> {}}:
with builtins;

let pulumi = pkgs.pulumi-bin.overrideDerivation (o: {
      srcs = builtins.filter (a: !isNull (builtins.match "pulumi(-resource-aws)*-v.*" a.name)) o.srcs;
    });
in pkgs.mkShell {
  buildInputs = [ pkgs.gopls pkgs.go pulumi ];
}
