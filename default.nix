{ pkgs ? import <nixpkgs> {} }:

let
  # There's a bug upstream. Using my fork until
  # https://github.com/mechpen/sockdump/pull/23 gets merged and
  # Nixpkgs bumped.
  sockdump = pkgs.sockdump.overrideAttrs(old: {
    src = pkgs.fetchFromGitHub {
      owner = "NinjaTrappeur";
      repo = "sockdump";
      rev = "5a45e06bc73938334de1375127e82d240b1d7477";
      hash = "sha256-q6jdwFhl2G9o2C0BVU6Xz7xizO00yaSQ2KSR/z4fixY=";
    };
  });
in pkgs.writeShellApplication {
  name = "snoop-nix-daemon";
  runtimeInputs = [ pkgs.wireshark sockdump ];
  text = ''
    sudo ls
    sudo sockdump --format pcap /nix/var/nix/daemon-socket/socket | wireshark -X lua_script:${./nix-packet.lua} -k -i -
  '';
}
