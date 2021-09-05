{
  description = "Hardenedlinux Zeek Scripts Repo";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "nixpkgs/release-21.05";
    flake-compat = { url = "github:edolstra/flake-compat"; flake = false; };
    devshell-flake.url = "github:numtide/devshell";
    zeek2nix.url = "github:hardenedlinux/zeek-nix";
    spicy-with-nix-flake.url = "github:GTrunSec/spicy-with-nix-flake";
    nixpkgs-hardenedlinux.url = "github:hardenedlinux/nixpkgs-hardenedlinux";
    nvfetcher = { url = "github:berberman/nvfetcher"; };
    gomod2nix.follows = "nixpkgs-hardenedlinux/gomod2nix";
  };
  outputs =
    { self
    , nixpkgs
    , flake-utils
    , flake-compat
    , devshell-flake
    , nvfetcher
    , zeek2nix
    , spicy-with-nix-flake
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
            devshell-flake.overlay
            nixpkgs-hardenedlinux.overlay
            nvfetcher.overlay
            spicy-with-nix-flake.overlay
            gomod2nix.overlay
            (final: prev: { zeek-release = zeek2nix.packages."${prev.system}".zeek-release; })
          ];
          config = {
            allowUnsupportedSystem = true;
          };
        };
      in
      rec {
        packages = flake-utils.lib.flattenTree rec {
          zeek-release = pkgs.zeek-release;
          hardenedlinux-zeek-scripts = pkgs.hardenedlinux-zeek-scripts;
        };

        hydraJobs = {
          inherit packages;
        };

        devShell = with pkgs; devshell.mkShell {
          imports = [
            (devshell.importTOML ./nix/devshell.toml)
          ];
          packages = [
            zeek-release
            (pkgs.python3.withPackages (ps: with ps;[
              btest
            ]))
            zed
          ];
          commands = [
            {
              name = pkgs.nvfetcher-bin.pname;
              help = pkgs.nvfetcher-bin.meta.description;
              command = "cd $DEVSHELL_ROOT/nix; ${pkgs.nvfetcher-bin}/bin/nvfetcher -c ./sources.toml --no-output $@";
            }
            {
              name = "zeek-with-dns";
              help = "launch zeek with protocols/dns scirpts";
              command = "${zeek-release}/bin/zeek ${hardenedlinux-zeek-scripts}/protocols/dns $@";
            }
          ];
        };
      }
      )
    );
}
