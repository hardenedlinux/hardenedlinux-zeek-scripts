{
  description = "Hardenedlinux Zeek Scripts Repo";
  nixConfig = {
    extra-experimental-features = "nix-command flakes";
    flake-registry = "https://github.com/hardenedlinux/flake-registry/raw/main/flake-registry.json";
    extra-trust-substituters = [
      "https://zeek.cachix.org"
    ];
    extra-trusted-public-keys = [
      "zeek.cachix.org-1:Jv0hB/P5eF7RQUZgSQiVqzqzgweP29YIwpSiukGlDWQ="
    ];
  };


  inputs = {
    flake-compat.flake = false;
    nixpkgs.follows = "nixpkgs-hardenedlinux/nixpkgs";
    cells.url = "/home/gtrun/ghq/github.com/GTrunSec/DevSecOps-cells";
  };
  outputs =
    { self
    , nixpkgs
    , flake-utils
    , flake-compat
    , devshell
    , zeek2nix
    , cells
    , nixpkgs-hardenedlinux
    }@inputs:
    {
      overlay = final: prev:
        {
          hardenedlinux-zeek-scripts-sources = prev.callPackage ./nix/_sources/generated.nix { };
          hardenedlinux-zeek-scripts = prev.callPackage ./nix/hardenedlinux-zeek-scripts.nix { };
        };
    }
    //
    (flake-utils.lib.eachSystem [ "x86_64-linux" "x86_64-darwin" ]
      (system:
      let
          pkgs = inputs.nixpkgs.legacyPackages."${system}".appendOverlays [
            self.overlay
            (final: prev: {
              inherit (zeek2nix.packages."${prev.system}")
                zeek-release
                zeek-latest;
              inherit (nixpkgs-hardenedlinux.packages."${prev.system}")
                btest
                zed
              ;
            })
          ];
          devshell = inputs.devshell.legacyPackages.${system};
      in
      rec {
        packages = flake-utils.lib.flattenTree rec {
          inherit (pkgs) hardenedlinux-zeek-scripts;
        };

        devShell = devshell.mkShell {
          imports = [
            (devshell.importTOML ./nix/devshell.toml)
            (devshell.importTOML ./nix/zed.toml)
            inputs.cells.devshellProfiles.${system}.tenzir-action
            inputs.cells.devshellProfiles.${system}.common
          ];
          packages = [ pkgs.zed ];
          commands = [
            {
              name = "zeek-with-dns";
              help = "launch zeek with protocols/dns scirpts";
              command = "${pkgs.zeek-release}/bin/zeek ${pkgs.hardenedlinux-zeek-scripts}/protocols/dns $@";
            }
          ];
        };
      })
    );
}
