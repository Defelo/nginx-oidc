{
  lib,
  pkgs,
  self,
}:

let
  eval = lib.evalModules {
    modules = [
      {
        config._module.check = false;
        config._module.args = { inherit pkgs; };
        options._module.args = lib.mkOption { internal = true; };
      }
      (import ./module.nix { inherit lib self; })
    ];
  };

  hideUpstreamOption =
    opt:
    if
      lib.elem opt.name [
        "services.nginx.virtualHosts"
        "services.nginx.virtualHosts.<name>.locations"
      ]
    then
      opt // { visible = false; }
    else
      opt;

  removeTrailingNewlineInLiteralExpression =
    opt:
    if opt.default._type or null == "literalExpression" then
      opt // { default = lib.literalExpression (lib.removeSuffix "\n" opt.default.text); }
    else
      opt;

  docs =
    (pkgs.nixosOptionsDoc {
      inherit (eval) options;
      transformOptions = lib.flip lib.pipe [
        hideUpstreamOption
        removeTrailingNewlineInLiteralExpression
      ];
    }).optionsCommonMark;
in

pkgs.runCommand "docs" { } ''
  ${lib.getExe pkgs.gnused} -E \
    's|\[${self}/(.*)\]\(.*\)|[\1](https://github.com/Defelo/nginx-oidc/blob/develop/\1)|' \
    ${docs} > $out
''
