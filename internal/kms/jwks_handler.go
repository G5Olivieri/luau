package kms

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/G5Olivieri/luau/jose/jwk"
	"github.com/G5Olivieri/luau/kms"
	"github.com/julienschmidt/httprouter"
)

type restJwk struct {
	Kty     jwk.KeyType  `json:"kty"`
	Use     *jwk.KeyUse  `json:"use,omitempty"`
	KeyOps  []jwk.KeyOps `json:"key_ops"`
	Alg     *jwk.KeyAlg  `json:"alg,omitempty"`
	Kid     *string      `json:"kid,omitempty"`
	X5u     string       `json:"x5u,omitempty" format:"uri"`
	X5c     []string     `json:"x5c,omitempty"`
	X5t     *string      `json:"x5t,omitempty"`
	X5tS256 *string      `json:"x5t#S256,omitempty"`

	// RSA Public Key
	E *string `json:"e,omitempty"`
	N *string `json:"n,omitempty"`

	// EC Public Key
	Curve *string `json:"crv,omitempty"`
	X     *string `json:"x,omitempty"`
	Y     *string `json:"y,omitempty"`
}

func fromJwk(k *jwk.JWK) *restJwk {
	var x5u string
	if k.X5u != nil {
		x5u = k.X5u.String()
	}
	return &restJwk{
		Kty:     k.Kty,
		Use:     k.Use,
		KeyOps:  k.KeyOps,
		Alg:     k.Alg,
		Kid:     k.Kid,
		X5u:     x5u,
		X5c:     k.X5c,
		X5t:     k.X5t,
		X5tS256: k.X5tS256,
		E:       k.E,
		N:       k.N,
		Curve:   k.Curve,
		X:       k.X,
		Y:       k.Y,
	}
}

type JwksHandler struct {
	kmsvalue kms.KMS
}

func NewJwksHandler(kmsvalue kms.KMS) JwksHandler {
	return JwksHandler{
		kmsvalue: kmsvalue,
	}
}

func (h JwksHandler) Handler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	keys, err := h.kmsvalue.GetPublicKeys(r.Context(), 256, 0)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	jwks := make([]*restJwk, 0, len(keys))
	for _, v := range keys {
		jwk, err := v.JWK()
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		jwks = append(jwks, fromJwk(jwk))
	}
	jwksResponse := make(map[string][]*restJwk)
	jwksResponse["keys"] = jwks
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(jwksResponse)
}
