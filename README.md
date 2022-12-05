# Learning OAuth2

[LUAU](https://en.wikipedia.org/wiki/L%C5%AB%CA%BBau) is pronounced `/ˈlo͞oou/`

# Tech Stack

- golang 1.19
  - go-gin

## Client Registration

- via CLI CTL

Example:

```bash
$ go build -o ./bin/luauctl cli.go
$ ./bin/luauctl db create
$ ./bin/luauctl clients create [NAME] [REDIRECT_URI]
```

## Sign up

- Hardcoded
  - `openidconnect/authenticate.go`

## Sign in

- OAuth2
  - [Authorization Code](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
  - [PKCE](https://oauth.net/2/pkce/) - not implemented

Example:

Redirect to signin

```
HTTP/1.1 302 Found
Location: https://luau.com/authenticate?
    response_type=code
    &scope=openid
    &client_id=
    &redirect_uri=
```

Request Token

```
POST /token HTTP/1.1
Server: https://luau.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
client_id=
redirect_uri=
```

## Session

- Stateless HMAC256 JWT
  - key is client_secret

- Register all of new sessions creation

## Sign out

- Delete JWT locally
