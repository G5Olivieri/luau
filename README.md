# Learning OAuth2

## AuthN

### CTL CLI

- for now cli updates database directly

### Sign up

Sign up a new user flow via CTL CLI:

- Create a new tinent
- Define authentication method to tinent
  - Only OAuth2 [PKCE](https://oauth.net/2/pkce/) is permitted for now (default)
  - Create a new client
  - Define redirect uri to client
- Create a new account to tinent
- Define username and password to account

### Sign in

- [Authorization Code](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)

### Session

- HMAC512 JWT

### Sign out

- Revoke JWT
- For now just delete local JWT

### Refresh Token

- WIP
