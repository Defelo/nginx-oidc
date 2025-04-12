{
  lib,
  self,
  testers,
}:

testers.runNixOSTest {
  name = "nginx-oidc";
  meta.maintainers = with lib.maintainers; [ defelo ];

  nodes.machine =
    { config, pkgs, ... }:

    let
      certs = pkgs.runCommand "certs" { } ''
        mkdir $out
        cd $out
        ${lib.getExe pkgs.minica} -domains 'localhost,id.localhost,whoami.localhost'
      '';

      kanidm = pkgs.kanidmWithSecretProvisioning;

      clientSecretFile = builtins.toFile "client-secret" "nTT6Ork2kMFwZcZ98OyHmXwd3PKWSlIc";
    in

    {
      imports = [ self.nixosModules.default ];

      services.kanidm = {
        enableServer = true;
        enableClient = true;
        package = kanidm;

        serverSettings = {
          domain = "id.localhost";
          origin = "https://id.localhost";

          bindaddress = "127.0.0.1:8001";
          trust_x_forward_for = true;

          tls_chain = "${certs}/localhost/cert.pem";
          tls_key = "${certs}/localhost/key.pem";
        };

        clientSettings = {
          uri = "https://id.localhost";
          ca_path = "${certs}/minica.pem";
        };

        provision = {
          enable = true;

          persons.user = {
            displayName = "Test User";
            mailAddresses = [ "user@example.com" ];
          };

          groups = {
            whoami_users.members = [ "user" ];
          };

          systems.oauth2 = {
            whoami = {
              displayName = "whoami";
              originUrl = "https://whoami.localhost${
                config.services.nginx.virtualHosts."whoami.localhost".locations."/".oidc.callbackPath
              }";
              originLanding = "https://whoami.localhost/";
              basicSecretFile = clientSecretFile;
              preferShortUsername = true;
              scopeMaps.whoami_users = [
                "openid"
                "email"
              ];
              claimMaps.roles.valuesByGroup = {
                whoami_users = [
                  "whoami"
                  "xyz"
                ];
              };
            };
          };
        };
      };

      services.whoami = {
        enable = true;
        port = 8000;
      };

      services.nginx = {
        enable = true;
        recommendedProxySettings = true;

        virtualHosts."whoami.localhost" = {
          sslCertificate = "${certs}/localhost/cert.pem";
          sslCertificateKey = "${certs}/localhost/key.pem";
          forceSSL = true;
          locations."/" = {
            proxyPass = "http://127.0.0.1:8000";
            oidc.enable = true;
          };
        };

        virtualHosts."id.localhost" = {
          sslCertificate = "${certs}/localhost/cert.pem";
          sslCertificateKey = "${certs}/localhost/key.pem";
          forceSSL = true;
          locations."/".proxyPass = "https://127.0.0.1:8001";
        };

        oidc = {
          enable = true;
          settings = {
            cookie_secret_path = builtins.toFile "cookie-secret" "super-secure-and-definitely-random-cookie-secret";
            ca_certs = [ "${certs}/minica.pem" ];
            clients."whoami.localhost" = {
              issuer = "https://id.localhost/oauth2/openid/whoami";
              client_id = "whoami";
              client_secret_path = clientSecretFile;
            };
          };
        };
      };

      security.pki.certificateFiles = [ "${certs}/minica.pem" ];

      networking.hosts = lib.genAttrs [ "127.0.0.1" "::1" ] (_: [
        "whoami.localhost"
        "id.localhost"
      ]);
    };

  interactive.nodes.machine = {
    virtualisation.graphics = false;
    services.openssh = {
      enable = true;
      settings = {
        PermitRootLogin = "yes";
        PermitEmptyPasswords = "yes";
      };
    };
    security.pam.services.sshd.allowNullPassword = true;
    virtualisation.forwardPorts = [
      {
        from = "host";
        host.port = 2222;
        guest.port = 22;
      }
    ];
  };

  testScript = ''
    import json
    import re

    machine.wait_for_unit("kanidm.service")
    machine.wait_for_unit("nginx-oidc.service")
    machine.wait_for_unit("nginx.service")
    machine.wait_for_unit("whoami.service")

    def search(*args, **kwargs):
      assert (match := re.search(*args, **kwargs))
      return match

    result = machine.succeed("kanidmd recover-account idm_admin -o json")
    idm_admin_password = json.loads(search(r'^\{"password".+$', result, re.M)[0])["password"]
    machine.succeed(f"KANIDM_PASSWORD=\"{idm_admin_password}\" kanidm login -D idm_admin")

    result = machine.succeed("kanidmd recover-account user -o json")
    user_password = json.loads(search(r'^\{"password".+$', result, re.M)[0])["password"]

    result = machine.succeed("kanidm person get user")
    user_id = search(r"^uuid: (.+)$", result, re.M)[1]

    curl = "curl --cookie cookies --cookie-jar cookies"

    resp = machine.succeed(f"{curl} -L https://whoami.localhost")
    assert "Authenticate to access whoami" in resp

    machine.succeed(f"{curl} https://id.localhost/ui/login/begin -d 'username=user&password=&totp='")
    resp = machine.succeed(f"{curl} https://id.localhost/ui/login/pw -L -d 'password={user_password}'")
    assert "Consent to Proceed to whoami" in resp
    consent_token = search("name=\"consent_token\" value=\"(.+)\"", resp)[1]

    resp = machine.succeed(f"{curl} https://id.localhost/ui/oauth2/consent -L -d 'consent_token={consent_token.replace("=", "%3d")}'")
    assert f"X-Auth-Sub: {user_id}" in resp
    assert "X-Auth-Name: Test User" in resp
    assert "X-Auth-Username: user" in resp
    assert "X-Auth-Email: user@example.com" in resp
    assert "X-Auth-Roles: whoami xyz" in resp

    resp = machine.succeed(f"{curl} https://whoami.localhost/")
    assert f"X-Auth-Sub: {user_id}" in resp
    assert "X-Auth-Name: Test User" in resp
    assert "X-Auth-Username: user" in resp
    assert "X-Auth-Email: user@example.com" in resp
    assert "X-Auth-Roles: whoami xyz" in resp

    machine.log(machine.succeed("SYSTEMD_COLORS=1 systemd-analyze security nginx-oidc.service --threshold=11 --no-pager"))
  '';
}
