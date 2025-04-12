# nginx-oidc

[OpenID Connect (OIDC)](https://openid.net/developers/how-connect-works/) Integration for [nginx](https://nginx.org/) via [`auth_request`](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)

nginx-oidc enables single sign-on (SSO) via any OIDC provider (e.g. [Kanidm](https://github.com/kanidm/kanidm), [Authentik](https://goauthentik.io/) or [Keycloak](https://www.keycloak.org/)) for any nginx site using the [`auth_request` module](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html).
It is primarily designed to run on [NixOS](https://nixos.org/), but should also work on any other Linux distribution.

## Features
- Stateless, easy to set up
- Supports public and confidential OIDC clients
- Enforces Proof Key for Code Exchange (PKCE)
- Optional role-based access control
- Bind session to user's ip address
- Send headers containing information about the authenticated user to the proxied service using [`proxy_set_header`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header)
- NixOS module

## NixOS Module Documentation
See [nixos-options.md](./nixos-options.md)

## Setup Instructions (NixOS)

1. Add this repository as an input to your `flake.nix`:
    ```nix
    {
      inputs.nginx-oidc.url = "github:Defelo/nginx-oidc";
    }
    ```
2. Add the module to your NixOS configuration:
    ```nix
    {
      imports = [nginx-oidc.nixosModules.default];
    }
    ```

### Server
The nginx-oidc server only needs to be reachable by nginx.
It is recommended to run both nginx and nginx-oidc on the same host and let nginx-oidc listen on a unix socket (configured automatically by the NixOS module if not explicitly changed).

1. Enable the nginx-oidc server by setting `services.nginx.oidc.enable = true;`.
2. (recommended) Generate a random cookie secret file (e.g. using `head -c 64 /dev/urandom`) and set `services.nginx.oidc.settings.cookie_secret_path` to the absolute path of this file. If this option is not set, a random secret is generated on each start, invalidating any previously issued auth/session cookies.
3. Configure your OIDC client(s) via the `services.nginx.oidc.settings.clients` option. You need to specify at least the `issuer` URL. The `client_id` defaults to the client name (attribute name). If you want to configure a confidential client, you need to specify the `client_secret_path`. Omit this option in case of a public client.

### Nginx Integration
Make sure your nginx is compiled with the `--with-http_auth_request_module` configure flag to include the [`ngx_http_auth_request_module`](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html).
[On NixOS this flag is already set](https://github.com/NixOS/nixpkgs/blob/472b4108d146d56eafdedaa30bb9376c4d139f89/pkgs/servers/http/nginx/generic.nix#L130).

1. Enable nginx-oidc for all locations you want to restrict by setting `services.nginx.virtualHosts.<name>.locations.<name>.oidc.enable = true;`
2. Set the `clientName` option to the name of the client configured in the nginx-oidc server you want to use. Defaults to the name of the virtual host if unset.
3. (optional) Set the `role` option to allow access to only users with a specific role.
4. If you set up the nginx-oidc server on a different host (not recommended), you need to set the `nginxOidcUrl` option accordingly.

## How it works
1. When a user tries to access a restricted location, nginx sends an HTTP request to `<nginx-oidc>/auth/<client>` which includes the session cookie (if set).
2. If the session cookie is valid and the user is authorized to access this location, nginx-oidc returns a `200 OK` and access is granted. Otherwise a `401 Unauthorized` is returned including a signed and encrypted auth cookie which contains the URL the user tried to access and the OAuth2 state and an `X-Auth-Redirect` header which nginx then translates into a redirect to the auth URL of the OIDC provider.
3. After logging in to the OIDC provider the user is redirected to the callback location on the same virtualHost as the restricted location which is proxied to `<nginx-oidc>/callback/<client>`. nginx-oidc then completes the OIDC flow by exchanging the authorization code for an access token and fetches the user's information from the OIDC provider. A signed and encrypted session cookie is set and the user is redirected back to the URL they originally came from.
4. If the session cookie has expired, nginx-oidc tries to refetch the user's information using the access/refresh tokens. If this fails, the user is redirected to the OIDC provider to reauthenticate.
