{
  description = "Nix wireshark dissector";

  inputs = {
    nixpkgs.url = "github:Ninjatrappeur/nixpkgs/nin/wireshark-dev-fix";
  };

  outputs = { self, nixpkgs }: {

    packages.x86_64-linux.snoop-nix-daemon = import ./default.nix { inherit (nixpkgs.legacyPackages.x86_64-linux) pkgs; };
    packages.x86_64-linux.default = self.packages.x86_64-linux.snoop-nix-daemon;
  };
}
