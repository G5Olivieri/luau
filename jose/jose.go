package jose

import (
	"net/url"

	"github.com/G5Olivieri/luau/jose/jwk"
)

type JoseRegisteredHeader struct {
	// https://www.rfc-editor.org/rfc/rfc7518
	Alg  string   `json:"alg"`
	Type *string  `json:"typ"`
	Jku  *url.URL `json:"jku"`
	Jwk  *jwk.JWK `json:"jwk"`
	Kid  *string  `json:"kid"`
}
