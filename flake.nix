{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs, ... }:

    let
      inherit (nixpkgs) lib;

      eachDefaultSystem = lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
    in

    {
      packages = eachDefaultSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = self.packages.${system}.nginx-oidc;

          nginx-oidc = pkgs.callPackage ./nix/package.nix { };

          test = pkgs.callPackage ./nix/test.nix { inherit self; };

          docs = pkgs.callPackage ./nix/docs.nix { inherit self; };

          generate = pkgs.writeShellScriptBin "generate" ''
            cd "$(${lib.getExe pkgs.git} rev-parse --show-toplevel)"

            ${lib.getExe pkgs.crate2nix} generate

            cat ${self.packages.${system}.docs} > nixos-options.md
          '';

          checks = pkgs.linkFarm "checks" (
            lib.removeAttrs self.packages.${system} [ "checks" ]
            // {
              devShells = pkgs.linkFarm "devShells" self.devShells.${system};
            }
          );
        }
      );

      nixosModules.default = import ./nix/module.nix { inherit lib self; };

      devShells = eachDefaultSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [ pkgs.crate2nix ];

            env = {
              RUST_LOG = "info,nginx_oidc=trace";
            };
          };
        }
      );

      formatter = eachDefaultSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        pkgs.treefmt.withConfig {
          settings = [
            ./treefmt.nix
            { _module.args = { inherit pkgs; }; }
          ];
        }
      );
    };
}
