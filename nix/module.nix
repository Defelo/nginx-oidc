{ lib, self }:

let
  # hasn't been backported to 24.11
  # TODO: remove after 25.05 has been released
  inherit (lib) concatMapAttrsStringSep;
in

{
  lib,
  config,
  pkgs,
  ...
}:

let
  settingsFormat = pkgs.formats.yaml { };
  cfg = config.services.nginx.oidc;

  listenAddressType = lib.head (lib.attrNames cfg.listenAddress);
  listenAddressTcp =
    let
      inherit (cfg.listenAddress.tcp) host port;
      hostWrapped = if lib.hasInfix ":" host then "[${host}]" else host;
    in
    "${lib.escapeShellArg hostWrapped}:${toString port}";
  listenAddressArg =
    {
      tcp = "--tcp ${listenAddressTcp}";
      unix = "--unix ${lib.escapeShellArg cfg.listenAddress.unix.path}";
    }
    .${listenAddressType};

  settings = cfg.settings // {
    cookie_secret_path = mkCred cfg.settings.cookie_secret_path;
    clients = lib.mapAttrs (
      _: client: client // { client_secret_path = mkCred client.client_secret_path; }
    ) cfg.settings.clients;
  };
  configFiles = [
    (settingsFormat.generate "config.yaml" settings)
  ] ++ map mkCred cfg.extraConfigFiles;
  configFileArgs = map (path: "--config ${lib.escapeShellArg path}") configFiles;

  hash = builtins.hashString "sha256";
  mkCred = x: if x != null then "/run/credentials/nginx-oidc.service/${hash x}" else x;
in

{
  meta.maintainers = with lib.maintainers; [ defelo ];
  _file = ./module.nix;

  options.services.nginx.oidc = {
    enable = lib.mkEnableOption "nginx-oidc";

    package = lib.mkPackageOption self.packages.${pkgs.system} "nginx-oidc" {
      pkgsText = "nginx-oidc.packages.\${system}";
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      description = "Log level of the nginx-oidc server. See <https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives> for more information.";
      default = "info";
    };

    extraConfigFiles = lib.mkOption {
      type = lib.types.listOf lib.types.path;
      description = "Extra configuration files to include.";
      default = [ ];
    };

    listenAddress = lib.mkOption {
      type = lib.types.attrTag {
        tcp = lib.mkOption {
          type = lib.types.submodule {
            _file = ./module.nix;
            options = {
              host = lib.mkOption {
                type = lib.types.str;
                description = "Host on which the server should listen.";
              };
              port = lib.mkOption {
                type = lib.types.port;
                description = "Port on which the server should listen.";
              };
            };
          };
          description = "Listen on a TCP socket.";
        };
        unix = lib.mkOption {
          type = lib.types.submodule {
            _file = ./module.nix;
            options = {
              path = lib.mkOption {
                type = lib.types.path;
                description = "Path of the unix socket on which the server should listen.";
              };
            };
          };
          description = "Listen on a unix socket.";
        };
      };
      description = "Where the server should listen for incoming connections.";
      default.unix.path = "/run/nginx-oidc/http.socket";
    };

    settings = lib.mkOption {
      type = lib.types.submodule {
        freeformType = settingsFormat.type;
        options = {
          cookie_secret_path = lib.mkOption {
            type = lib.types.nullOr lib.types.path;
            description = "Path of the file containing the secret used to sign and encrypt session cookies. If unset, a random secret is generated on each run.";
            default = null;
          };

          ca_certs = lib.mkOption {
            type = lib.types.listOf lib.types.path;
            description = "List of paths of additional CA certificates to trust.";
            default = [ ];
          };

          clients = lib.mkOption {
            type = lib.types.attrsOf (
              lib.types.submodule (
                { name, ... }:
                {
                  freeformType = settingsFormat.type;
                  options = {
                    issuer = lib.mkOption {
                      type = lib.types.str;
                      description = "Issuer URL of the OIDC client (without the `/.well-known/openid-configuration` suffix)";
                    };

                    client_id = lib.mkOption {
                      type = lib.types.str;
                      description = "Client ID of the OIDC client. Defaults to the attribute name.";
                    };

                    client_secret_path = lib.mkOption {
                      type = lib.types.nullOr lib.types.path;
                      description = "Path of the file containing the client secret of the OIDC client. Set to `null` for public clients.";
                      default = null;
                    };

                    scopes = lib.mkOption {
                      type = lib.types.listOf lib.types.str;
                      description = "Scopes to request from the OIDC provider.";
                      default = [
                        "openid"
                        "email"
                      ];
                    };

                    roles_claim = lib.mkOption {
                      type = lib.types.nullOr lib.types.str;
                      description = "OIDC claim which contains a list of the user's roles.";
                      default = "roles";
                    };

                    auth_cookie_ttl_secs = lib.mkOption {
                      type = lib.types.ints.unsigned;
                      description = "Number of seconds the auth cookie is valid. This cookie is used to remember the original URL and authentication state when the user is redirected to the OIDC provider.";
                      default = 600;
                    };

                    session_cookie_ttl_secs = lib.mkOption {
                      type = lib.types.ints.unsigned;
                      description = "Number of seconds the session cookie is valid. After the session cookie has expired nginx-oidc first tries to refetch the user's information by using the access and refresh tokens. The user is only redirected to the OIDC provider if these attempts do not succeed.";
                      default = 60;
                    };

                    keep_access_token = lib.mkOption {
                      type = lib.types.bool;
                      description = "Whether to remember the OIDC access token after a successful authorization.";
                      default = true;
                    };

                    keep_refresh_token = lib.mkOption {
                      type = lib.types.bool;
                      description = "Whether to remember the OIDC refresh token after a successful authorization.";
                      default = true;
                    };

                    real_ip_header = lib.mkOption {
                      type = lib.types.nullOr lib.types.str;
                      description = "Header which contains the user's real ip. If unset, the session is not bound to the user's ip address.";
                      default = "X-Real-Ip";
                    };
                  };

                  config = {
                    client_id = lib.mkDefault name;
                  };
                }
              )
            );
            description = "OIDC clients";
            default = { };
          };
        };
      };
      description = "Configuration of the nginx-oidc server.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.nginx-oidc = {
      wantedBy = [ "multi-user.target" ];

      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];

      environment.RUST_LOG = cfg.logLevel;

      serviceConfig = {
        User = "nginx-oidc";
        Group = "nginx-oidc";
        DynamicUser = true;
        RuntimeDirectory = "nginx-oidc";

        LoadCredential =
          let
            clientSecrets = lib.mapAttrsToList (_: client: client.client_secret_path) cfg.settings.clients;
            secrets = lib.filter (x: x != null) (
              [ cfg.settings.cookie_secret_path ] ++ clientSecrets ++ cfg.extraConfigFiles
            );
          in
          map (s: "${hash s}:${s}") secrets;

        ExecStart = "${lib.getExe cfg.package} serve ${listenAddressArg} ${toString configFileArgs}";

        ExecStartPost =
          lib.mkIf (config.services.nginx.enable && cfg.listenAddress ? unix)
            "+${pkgs.writeShellScript "nginx-oidc-post-start" ''
              until [[ -e ${lib.escapeShellArg cfg.listenAddress.unix.path} ]]; do sleep 1; done
              ${lib.getExe' pkgs.acl "setfacl"} -m u:${lib.escapeShellArg config.services.nginx.user}:rw ${lib.escapeShellArg cfg.listenAddress.unix.path}
            ''}";

        # Hardening
        AmbientCapabilities = [ "" ];
        CapabilityBoundingSet = [ "" ];
        DevicePolicy = "closed";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        PrivateUsers = true;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RemoveIPC = true;
        RestrictAddressFamilies = [ "AF_INET AF_INET6 AF_UNIX" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SocketBindAllow = lib.mkIf (cfg.listenAddress ? tcp) "tcp:${toString cfg.listenAddress.tcp.port}";
        SocketBindDeny = "any";
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
          "~@resources"
        ];
        UMask = "0077";
      };
    };
  };

  options.services.nginx.virtualHosts = lib.mkOption {
    type = lib.types.attrsOf (
      lib.types.submodule (
        { name, ... }@vhost:
        let
          prefixFor = location: "_nginx_oidc_${hash "${vhost.name} ${location}"}";
        in
        {
          options.locations = lib.mkOption {
            type = lib.types.attrsOf (
              lib.types.submodule (
                { name, ... }@location:
                let
                  prefix = prefixFor location.name;
                in
                {
                  options.oidc = {
                    enable = lib.mkEnableOption "OIDC auth for this location";

                    nginxOidcUrl = lib.mkOption {
                      type = lib.types.str;
                      description = "Base URL of the nginx-oidc server which nginx should use.";
                      defaultText = lib.literalExpression ''
                        {
                          tcp = "http://''${listenAddressTcp}";
                          unix = "http://unix:''${listenAddressUnix}:";
                        }.''${listenAddressType}
                      '';
                    };

                    clientName = lib.mkOption {
                      type = lib.types.str;
                      description = "Name of the client configured in nginx-oidc. Defaults to the `virtualHosts` attribute name.";
                    };

                    role = lib.mkOption {
                      type = lib.types.nullOr lib.types.str;
                      description = "Name of a role a user has to have in order to be granted access.";
                      default = null;
                    };

                    callbackPath = lib.mkOption {
                      type = lib.types.strMatching "^/.*$";
                      description = "Path for the OAuth2 redirect URL.";
                      defaultText = lib.literalExpression ''
                        "/''${prefix}/callback"
                      '';
                    };

                    headers = {
                      sub = lib.mkOption {
                        type = lib.types.nullOr lib.types.str;
                        description = "Header to set via `proxy_set_header` containing the `subject` claim (unique user identifier).";
                        default = "X-Auth-Sub";
                      };

                      name = lib.mkOption {
                        type = lib.types.nullOr lib.types.str;
                        description = "Header to set via `proxy_set_header` containing the `name` claim (display name of the user).";
                        default = "X-Auth-Name";
                      };

                      username = lib.mkOption {
                        type = lib.types.nullOr lib.types.str;
                        description = "Header to set via `proxy_set_header` containing the `preferred_username` claim.";
                        default = "X-Auth-Username";
                      };

                      email = lib.mkOption {
                        type = lib.types.nullOr lib.types.str;
                        description = "Header to set via `proxy_set_header` containing the `email` claim.";
                        default = "X-Auth-Email";
                      };

                      roles = lib.mkOption {
                        type = lib.types.nullOr lib.types.str;
                        description = "Header to set via `proxy_set_header` containing the roles of the user.";
                        default = "X-Auth-Roles";
                      };
                    };
                  };

                  config = {
                    oidc = {
                      nginxOidcUrl = lib.mkIf cfg.enable (
                        lib.mkDefault
                          {
                            tcp = "http://${listenAddressTcp}";
                            unix = "http://unix:${cfg.listenAddress.unix.path}:";
                          }
                          .${listenAddressType}
                      );

                      clientName = lib.mkDefault vhost.name;

                      callbackPath = lib.mkDefault "/${prefix}/callback";
                    };

                    extraConfig = lib.mkIf location.config.oidc.enable ''
                      auth_request .${prefix}_auth;
                      auth_request_set $auth_redirect $upstream_http_x_auth_redirect;
                      auth_request_set $auth_cookie $upstream_http_set_cookie;
                      error_page 401 =307 $auth_redirect;
                      more_set_headers "Set-Cookie: $auth_cookie";

                      auth_request_set $auth_sub $upstream_http_x_auth_sub;
                      auth_request_set $auth_name $upstream_http_x_auth_name;
                      auth_request_set $auth_username $upstream_http_x_auth_username;
                      auth_request_set $auth_email $upstream_http_x_auth_email;
                      auth_request_set $auth_roles $upstream_http_x_auth_roles;

                      ${concatMapAttrsStringSep "\n" (
                        name: value: "proxy_set_header ${value} $auth_${name};"
                      ) location.config.oidc.headers}
                    '';
                  };
                }
              )
            );
          };

          config.extraConfig =
            let
              mkLocationConfig =
                name: location:
                let
                  prefix = prefixFor name;
                in
                ''
                  location .${prefix}_auth {
                    internal;
                    proxy_pass ${location.oidc.nginxOidcUrl}/auth/${location.oidc.clientName}${
                      lib.optionalString (location.oidc.role != null) "?role=${location.oidc.role}"
                    };
                    proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
                    proxy_set_header X-Callback-Path ${location.oidc.callbackPath};
                    proxy_pass_request_body off;
                    proxy_set_header Content-Length "";
                    proxy_set_header X-Real-Ip $remote_addr;
                  }
                  location = ${location.oidc.callbackPath} {
                    proxy_pass ${location.oidc.nginxOidcUrl}/callback/${location.oidc.clientName};
                    proxy_set_header X-Real-Ip $remote_addr;
                  }
                '';
            in
            lib.pipe vhost.config.locations [
              (lib.filterAttrs (_: location: location.oidc.enable))
              (lib.mapAttrsToList mkLocationConfig)
              lib.mkMerge
            ];
        }
      )
    );
  };
}
