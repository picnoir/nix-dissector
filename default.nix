{ pkgs ? import <nixpkgs> {} }:

pkgs.stdenv.mkDerivation {
  pname = "nix-dissector";
  version = "1.0";
  nativeBuildInputs = [ pkgs.autoreconfHook pkgs.pkg-config ];
  buildInputs = [ pkgs.wireshark.dev pkgs.glib ];
  src = pkgs.lib.cleanSource ./.;

}
