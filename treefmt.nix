{ lib, pkgs, ... }:

{
  tree-root-file = ".git/config";
  on-unmatched = "warn";

  excludes = [
    "*.lock"
    "*.md"
    ".envrc"
    ".gitattributes"
    ".gitignore"
    "Cargo.nix"
  ];

  formatter.nixfmt = {
    command = lib.getExe pkgs.nixfmt-rfc-style;
    includes = [ "*.nix" ];
    options = [ "--strict" ];
  };

  formatter.prettier = {
    command = lib.getExe pkgs.nodePackages.prettier;
    includes = [
      "*.json"
      "*.yml"
    ];
    options = [ "--write" ];
  };

  formatter.rustfmt = {
    command = lib.getExe pkgs.rustfmt;
    includes = [ "*.rs" ];
    options = [
      "--config=skip_children=true"
      "--edition=2024"
    ];
  };

  formatter.taplo = {
    command = lib.getExe pkgs.taplo;
    includes = [ "*.toml" ];
    options = [
      "format"
      "--option=column_width=120"
      "--option=align_comments=false"
    ];
  };
}
