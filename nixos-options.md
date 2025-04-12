## services\.nginx\.oidc\.enable

Whether to enable nginx-oidc\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.package



The nginx-oidc package to use\.



*Type:*
package



*Default:*
` nginx-oidc.packages.${system}.nginx-oidc `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.extraConfigFiles



Extra configuration files to include\.



*Type:*
list of absolute path



*Default:*
` [ ] `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.listenAddress



Where the server should listen for incoming connections\.



*Type:*
attribute-tagged union



*Default:*

```
{
  unix = {
    path = "/run/nginx-oidc/http.socket";
  };
}
```

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.listenAddress\.tcp



Listen on a TCP socket\.



*Type:*
submodule

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.listenAddress\.tcp\.host



Host on which the server should listen\.



*Type:*
string

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.listenAddress\.tcp\.port



Port on which the server should listen\.



*Type:*
16 bit unsigned integer; between 0 and 65535 (both inclusive)

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.listenAddress\.unix



Listen on a unix socket\.



*Type:*
submodule

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.listenAddress\.unix\.path



Path of the unix socket on which the server should listen\.



*Type:*
absolute path

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.logLevel



Log level of the nginx-oidc server\. See [https://docs\.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct\.EnvFilter\.html\#directives](https://docs\.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct\.EnvFilter\.html\#directives) for more information\.



*Type:*
string



*Default:*
` "info" `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.settings



Configuration of the nginx-oidc server\.



*Type:*
YAML value

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.settings\.ca_certs



List of paths of additional CA certificates to trust\.



*Type:*
list of absolute path



*Default:*
` [ ] `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.settings\.clients



OIDC clients



*Type:*
attribute set of (YAML value)



*Default:*
` { } `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.settings\.clients\.\<name>\.auth_cookie_ttl_secs



Number of seconds the auth cookie is valid\. This cookie is used to remember the original URL and authentication state when the user is redirected to the OIDC provider\.



*Type:*
unsigned integer, meaning >=0



*Default:*
` 600 `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.settings\.clients\.\<name>\.client_id



Client ID of the OIDC client\. Defaults to the attribute name\.



*Type:*
string

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.settings\.clients\.\<name>\.client_secret_path



Path of the file containing the client secret of the OIDC client\. Set to ` null ` for public clients\.



*Type:*
null or absolute path



*Default:*
` null `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.settings\.clients\.\<name>\.issuer



Issuer URL of the OIDC client (without the ` /.well-known/openid-configuration ` suffix)



*Type:*
string

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.settings\.clients\.\<name>\.keep_access_token



Whether to remember the OIDC access token after a successful authorization\.



*Type:*
boolean



*Default:*
` true `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.settings\.clients\.\<name>\.keep_refresh_token



Whether to remember the OIDC refresh token after a successful authorization\.



*Type:*
boolean



*Default:*
` true `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.settings\.clients\.\<name>\.real_ip_header



Header which contains the user’s real ip\. If unset, the session is not bound to the user’s ip address\.



*Type:*
null or string



*Default:*
` "X-Real-Ip" `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.settings\.clients\.\<name>\.roles_claim



OIDC claim which contains a list of the user’s roles\.



*Type:*
null or string



*Default:*
` "roles" `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.settings\.clients\.\<name>\.scopes



Scopes to request from the OIDC provider\.



*Type:*
list of string



*Default:*

```
[
  "openid"
  "email"
]
```

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.settings\.clients\.\<name>\.session_cookie_ttl_secs



Number of seconds the session cookie is valid\. After the session cookie has expired nginx-oidc first tries to refetch the user’s information by using the access and refresh tokens\. The user is only redirected to the OIDC provider if these attempts do not succeed\.



*Type:*
unsigned integer, meaning >=0



*Default:*
` 60 `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.oidc\.settings\.cookie_secret_path



Path of the file containing the secret used to sign and encrypt session cookies\. If unset, a random secret is generated on each run\.



*Type:*
null or absolute path



*Default:*
` null `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.virtualHosts\.\<name>\.locations\.\<name>\.oidc\.enable



Whether to enable OIDC auth for this location\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.virtualHosts\.\<name>\.locations\.\<name>\.oidc\.callbackPath



Path for the OAuth2 redirect URL\.



*Type:*
string matching the pattern ^/\.\*$



*Default:*
` "/${prefix}/callback" `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.virtualHosts\.\<name>\.locations\.\<name>\.oidc\.clientName



Name of the client configured in nginx-oidc\. Defaults to the ` virtualHosts ` attribute name\.



*Type:*
string

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.virtualHosts\.\<name>\.locations\.\<name>\.oidc\.headers\.email



Header to set via ` proxy_set_header ` containing the ` email ` claim\.



*Type:*
null or string



*Default:*
` "X-Auth-Email" `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.virtualHosts\.\<name>\.locations\.\<name>\.oidc\.headers\.name



Header to set via ` proxy_set_header ` containing the ` name ` claim (display name of the user)\.



*Type:*
null or string



*Default:*
` "X-Auth-Name" `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.virtualHosts\.\<name>\.locations\.\<name>\.oidc\.headers\.roles



Header to set via ` proxy_set_header ` containing the roles of the user\.



*Type:*
null or string



*Default:*
` "X-Auth-Roles" `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.virtualHosts\.\<name>\.locations\.\<name>\.oidc\.headers\.sub



Header to set via ` proxy_set_header ` containing the ` subject ` claim (unique user identifier)\.



*Type:*
null or string



*Default:*
` "X-Auth-Sub" `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.virtualHosts\.\<name>\.locations\.\<name>\.oidc\.headers\.username



Header to set via ` proxy_set_header ` containing the ` preferred_username ` claim\.



*Type:*
null or string



*Default:*
` "X-Auth-Username" `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.virtualHosts\.\<name>\.locations\.\<name>\.oidc\.nginxOidcUrl



Base URL of the nginx-oidc server which nginx should use\.



*Type:*
string



*Default:*

```
{
  tcp = "http://${listenAddressTcp}";
  unix = "http://unix:${listenAddressUnix}:";
}.${listenAddressType}
```

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)



## services\.nginx\.virtualHosts\.\<name>\.locations\.\<name>\.oidc\.role



Name of a role a user has to have in order to be granted access\.



*Type:*
null or string



*Default:*
` null `

*Declared by:*
 - [nix/module\.nix](https://git.defelo.de/Defelo/nginx-oidc/src/branch/develop/nix/module\.nix)


