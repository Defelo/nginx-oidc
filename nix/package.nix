{
  callPackage,
  installShellFiles,
  lib,
  stdenv,
  versionCheckHook,
}:

let
  cargoNix = callPackage ../Cargo.nix { };

  unwrapped = cargoNix.rootCrate.build.overrideAttrs {
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../src
        ../config.yml
      ];
    };
  };
in

stdenv.mkDerivation {
  pname = "nginx-oidc";
  inherit (unwrapped) version;

  src = unwrapped;

  nativeBuildInputs = [ installShellFiles ];

  installPhase = ''
    runHook preInstall

    cp -r . $out
    installShellCompletion --cmd nginx-oidc \
      --bash <(COMPLETE=bash $out/bin/nginx-oidc) \
      --fish <(COMPLETE=fish $out/bin/nginx-oidc) \
      --zsh <(COMPLETE=zsh $out/bin/nginx-oidc)

    runHook postInstall
  '';

  nativeInstallCheckInputs = [ versionCheckHook ];
  versionCheckProgramArg = "--version";
  doInstallCheck = true;

  passthru = { inherit unwrapped; };

  meta = {
    description = "OpenID Connect Integration for nginx via auth_request";
    homepage = "https://github.com/Defelo/nginx-oidc";
    license = lib.licenses.mit;
    mainProgram = "nginx-oidc";
    maintainers = with lib.maintainers; [ defelo ];
  };
}
