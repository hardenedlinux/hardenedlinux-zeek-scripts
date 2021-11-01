{
  description = "Hardenedlinux Zeek Scripts Repo";

  inputs = {
    zeek2nix = { url = "github:hardenedlinux/zeek2nix"; };

    flake-utils.follows = "zeek2nix/flake-utils";
    nixpkgs.follows = "zeek2nix/nixpkgs";
    nixpkgs-hardenedlinux.follows = "zeek2nix/nixpkgs-hardenedlinux";
    nvfetcher.follows = "zeek2nix/nvfetcher";
    devshell.follows = "zeek2nix/devshell";
    flake-compat = { follows = "zeek2nix/flake-compat"; flake = false; };
    gomod2nix.follows = "zeek2nix/nixpkgs-hardenedlinux/gomod2nix";
  };
  outputs =
    { self
    , nixpkgs
    , flake-utils
    , flake-compat
    , devshell
    , nvfetcher
    , zeek2nix
    , nixpkgs-hardenedlinux
    , gomod2nix
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
            nixpkgs-hardenedlinux.overlay
            nvfetcher.overlay
            gomod2nix.overlay
            (final: prev: {
              zeek-release = zeek2nix.packages."${prev.system}".zeek-release;
              zeek-latest = zeek2nix.packages."${prev.system}".zeek-latest;
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
              name = pkgs.nvfetcher-bin.pname;
              help = pkgs.nvfetcher-bin.meta.description;
              command = "export NIX_PATH=nixpkgs=${pkgs.path}; cd $PRJ_ROOT/nix; ${pkgs.nvfetcher-bin}/bin/nvfetcher -c ./sources.toml $@";
            }
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
