# Learning OAuth2 (LUAU)

# Tech Stack

- golang 1.19
  - go-gin

## Client Registration

- Hardcoded
  - `openidconnect/client_repository.go`

## Sign up

- Hardcoded
  - `openidconnect/authenticate.go`

## Sign in

- OAuth2
  - [Authorization Code](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
  - [PKCE](https://oauth.net/2/pkce/)

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
  - secret is client_secret

## Sign out

- Delete JWT locally
