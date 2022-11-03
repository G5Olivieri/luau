# Learning OAuth2

# Tech Stack

- golang 1.19
  - go-gin
- SQLite3 (db/luau.db)

## AuthN

### CTL CLI

- updates database directly

### Sign up

Sign up a new user flow via CTL CLI:

- Create a new client
  - Define redirect uri to client
- Create a new account to tinent
- Define username and password to account

### Sign in

- OAuth2
  - [Authorization Code](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
  - [PKCE](https://oauth.net/2/pkce/)

Example

```
HTTP/1.1 302 Found
Location: https://luau.com/tinent/123/authorize?
    response_type=code
    &scope=openid
    &client_id=
    &redirect_uri=
    &code_challenge=
    &code_challenge_method=
    &state=
```

### Session

- Stateless HMAC512 JWT

### Sign out

- delete JWT locally
