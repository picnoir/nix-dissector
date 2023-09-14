{ pkgs ? import <nixpkgs> {} }:
let
  sockdump = pkgs.sockdump.overrideAttrs(old: {
    src = pkgs.fetchFromGitHub {
      owner = "NinjaTrappeur";
      repo = "sockdump";
      rev = "5a45e06bc73938334de1375127e82d240b1d7477";
      hash = "sha256-q6jdwFhl2G9o2C0BVU6Xz7xizO00yaSQ2KSR/z4fixY=";
    };
  });
in pkgs.mkShell {
  nativeBuildInputs = [ sockdump pkgs.wireshark ];
}
