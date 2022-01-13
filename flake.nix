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
  };
  outputs =
    { self
    , nixpkgs
    , flake-utils
    , flake-compat
    , devshell
    , zeek2nix
    , nixpkgs-hardenedlinux
    }:
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
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            self.overlay
            devshell.overlay
            (final: prev: {
              inherit (zeek2nix.packages."${prev.system}")
                zeek-release
                zeek-latest;
              inherit (nixpkgs-hardenedlinux.packages."${prev.system}")
                btest
                zed;
            })
          ];
          config = {
            allowUnsupportedSystem = true;
          };
        };
      in
      rec {
        packages = flake-utils.lib.flattenTree rec {
          zeek-release = pkgs.zeek-release;
          zeek-latest = pkgs.zeek-latest;
          hardenedlinux-zeek-scripts = pkgs.hardenedlinux-zeek-scripts;
        };

        hydraJobs = {
          inherit packages;
        };

        devShell = with pkgs; pkgs.devshell.mkShell {
          imports = [
            (pkgs.devshell.importTOML ./nix/devshell.toml)
            (pkgs.devshell.importTOML ./nix/zed.toml)
          ];
          packages = [
            zeek-release
            (pkgs.python3.withPackages (ps: with ps;[
              btest
            ]))
          ];
          commands = [
            {
              name = "zeek-with-dns";
              help = "launch zeek with protocols/dns scirpts";
              command = "${zeek-release}/bin/zeek ${hardenedlinux-zeek-scripts}/protocols/dns $@";
            }
          ];
        };
      })
    );
}
