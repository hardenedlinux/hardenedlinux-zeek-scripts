{
  description = "Hardenedlinux Zeek Scripts Repo";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-compat = { url = "github:edolstra/flake-compat"; flake = false; };
    devshell-flake.url = "github:numtide/devshell";
    zeek-flake.url = "github:hardenedlinux/zeek-nix";
    nvfetcher-flake = {
      url = "github:berberman/nvfetcher";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = { self, nixpkgs, flake-utils, flake-compat, devshell-flake, nvfetcher-flake, zeek-flake }:
    {
      overlay = final: prev:
        {
          sources = (import ./sources.nix) { inherit (final) fetchurl fetchgit; };
        };
    }
    //
    (flake-utils.lib.eachSystem [ "x86_64-linux" "x86_64-darwin" ]
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              self.overlay
              devshell-flake.overlay
              zeek-flake.overlay
            ];
            config = {
              allowUnsupportedSystem = true;
            };
          };
        in
        rec {
          packages = flake-utils.lib.flattenTree rec {
            zeekTLS = pkgs.zeekTLS;
          };

          hydraJobs = {
            inherit packages;
          };

          devShell = with pkgs; devshell.mkShell {
            imports = [
              (devshell.importTOML ./devshell.toml)
            ];
            packages = [
              zeekTLS
            ];
          };
        }
      )
    );
}
