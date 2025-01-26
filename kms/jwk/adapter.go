package jwk

import (
	"errors"
	"strings"

	"github.com/G5Olivieri/luau/jose/jwk"
	"github.com/G5Olivieri/luau/kms"
	"github.com/G5Olivieri/luau/kms/internal"
)

func KeyFromJWK(k *jwk.JWK) (kms.Key, error) {
	if k.Kid == nil || k.Use == nil || k.Alg == nil {
		return nil, errors.ErrUnsupported
	}

	if strings.HasPrefix(k.Alg.String(), "HS") {
		return internal.HMACKeyFromJWK(k)
	}

	if strings.HasPrefix(k.Alg.String(), "RS") {
		return internal.RSAKeyFromJWK(k)
	}

	if strings.HasPrefix(k.Alg.String(), "PS") {
		return internal.RSAKeyFromJWK(k)
	}

	if strings.HasPrefix(k.Alg.String(), "ES") {
		return internal.ECKeyFromJWK(k)
	}

	return nil, errors.ErrUnsupported
}
