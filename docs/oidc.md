# [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html)

- [OpenID Conformance Test Suite](https://gitlab.com/openid/conformance-suite/)

## [TLS](https://openid.net/specs/openid-connect-core-1_0.html#TLSRequirements)

## Authentication

## /oidc/auth
- [GET and POST method are allowed](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
- GET and POST use `application/x-www-form-urlencoded` serialization
- [Request and response parameters MUST NOT be included more than once.](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1)
- [JSONSchema](./auth.schema.json)


## /oidc/token

## Internals
### Authentication
/signin
    Username + Password
    WebAuthn + Public Key
### Multi-factor Authentication (MFA)
/mfa/totp
/mfa/sms
/mfa/email
/mfa/facial-biometrics

/signup
