// https://www.rfc-editor.org/rfc/rfc7515.html
package jwt

type URI string

type JoseRegisteredHeader struct {
	// https://www.rfc-editor.org/rfc/rfc7518
	Alg string  `json:"alg"`
	Jku *URI    `json:"jku"`
	Jwk *JWK    `json:"jwk"`
	Kid *string `json:"kid"`
}
