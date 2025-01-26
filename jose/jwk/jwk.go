// https://datatracker.ietf.org/doc/html/rfc7517
package jwk

import (
	"crypto/elliptic"
	"errors"
	"net/url"

	pb "github.com/G5Olivieri/luau/jose/jose"
)

var (
	ErrKeyTypMustBePresent = errors.New("key typ must be present")
)

type KeyOps string
type KeyAlg string
type KeyUse string
type KeyType string

var (
	KeyOpsSign       KeyOps = "sign"
	KeyOpsVerify     KeyOps = "verify"
	KeyOpsEncrypt    KeyOps = "encrypt"
	KeyOpsDecrypt    KeyOps = "decrypt"
	KeyOpsWrapKey    KeyOps = "wrapKey"
	KeyOpsUnwrapKey  KeyOps = "unwrapKey"
	KeyOpsDeriveKey  KeyOps = "deriveKey"
	KeyOpsDeriveBits KeyOps = "deriveBits"

	KeyAlgHS256 KeyAlg = "HS256"
	KeyAlgHS384 KeyAlg = "HS384"
	KeyAlgHS512 KeyAlg = "HS512"

	KeyAlgRS256 KeyAlg = "RS256"
	KeyAlgRS384 KeyAlg = "RS384"
	KeyAlgRS512 KeyAlg = "RS512"

	KeyAlgPS256 KeyAlg = "PS256"
	KeyAlgPS384 KeyAlg = "PS384"
	KeyAlgPS512 KeyAlg = "PS512"

	KeyAlgES256 KeyAlg = "ES256"
	KeyAlgES384 KeyAlg = "ES384"
	KeyAlgES512 KeyAlg = "ES512"

	KeyUseSig KeyUse = "sig"
	KeyUseEnc KeyUse = "enc"

	KeyTypeOct KeyType = "oct"
	KeyTypeEC  KeyType = "EC"
	KeyTypeRSA KeyType = "RSA"
)

type JWK struct {
	Kty     KeyType
	Use     *KeyUse
	KeyOps  []KeyOps
	Alg     *KeyAlg
	Kid     *string
	X5u     *url.URL
	X5c     []string
	X5t     *string
	X5tS256 *string

	// oct
	K *string

	// RSA Public Key
	E *string
	N *string

	// RSA Private Key
	Dp *string
	Dq *string
	Qi *string

	// EC Public Key
	Curve *string
	X     *string
	Y     *string

	// EC and RSA Private Key
	D *string
}

func (a KeyAlg) String() string {
	return string(a)
}

func KeyAlgFromProtobuf(alg pb.JWKAlg) *KeyAlg {
	switch alg {
	case pb.JWKAlg_JWK_ALG_HS256:
		return &KeyAlgHS256
	case pb.JWKAlg_JWK_ALG_HS384:
		return &KeyAlgHS384
	case pb.JWKAlg_JWK_ALG_HS512:
		return &KeyAlgHS512
	case pb.JWKAlg_JWK_ALG_RS256:
		return &KeyAlgRS256
	case pb.JWKAlg_JWK_ALG_RS384:
		return &KeyAlgRS384
	case pb.JWKAlg_JWK_ALG_RS512:
		return &KeyAlgRS512
	case pb.JWKAlg_JWK_ALG_PS256:
		return &KeyAlgPS256
	case pb.JWKAlg_JWK_ALG_PS384:
		return &KeyAlgPS384
	case pb.JWKAlg_JWK_ALG_PS512:
		return &KeyAlgPS512
	case pb.JWKAlg_JWK_ALG_ES256:
		return &KeyAlgES256
	case pb.JWKAlg_JWK_ALG_ES384:
		return &KeyAlgES384
	case pb.JWKAlg_JWK_ALG_ES512:
		return &KeyAlgES512
	default:
		return nil
	}
}

func (a *KeyAlg) Protobuf() pb.JWKAlg {
	if a == nil {
		return pb.JWKAlg_JWK_ALG_UNSPECIFIED
	}
	switch *a {
	case KeyAlgHS256:
		return pb.JWKAlg_JWK_ALG_HS256
	case KeyAlgHS384:
		return pb.JWKAlg_JWK_ALG_HS384
	case KeyAlgHS512:
		return pb.JWKAlg_JWK_ALG_HS512
	case KeyAlgRS256:
		return pb.JWKAlg_JWK_ALG_RS256
	case KeyAlgRS384:
		return pb.JWKAlg_JWK_ALG_RS384
	case KeyAlgRS512:
		return pb.JWKAlg_JWK_ALG_RS512
	case KeyAlgPS256:
		return pb.JWKAlg_JWK_ALG_PS256
	case KeyAlgPS384:
		return pb.JWKAlg_JWK_ALG_PS384
	case KeyAlgPS512:
		return pb.JWKAlg_JWK_ALG_PS512
	case KeyAlgES256:
		return pb.JWKAlg_JWK_ALG_ES256
	case KeyAlgES384:
		return pb.JWKAlg_JWK_ALG_ES384
	case KeyAlgES512:
		return pb.JWKAlg_JWK_ALG_ES512
	default:
		return pb.JWKAlg_JWK_ALG_UNSPECIFIED
	}
}

func KeyTypeFromProtobuf(typ pb.JWKType) *KeyType {
	switch typ {
	case pb.JWKType_JWK_TYPE_EC:
		return &KeyTypeEC
	case pb.JWKType_JWK_TYPE_RSA:
		return &KeyTypeRSA
	case pb.JWKType_JWK_TYPE_OCT:
		return &KeyTypeOct
	default:
		return nil
	}
}

func (t *KeyType) Protobuf() pb.JWKType {
	switch *t {
	case KeyTypeEC:
		return pb.JWKType_JWK_TYPE_EC
	case KeyTypeRSA:
		return pb.JWKType_JWK_TYPE_RSA
	case KeyTypeOct:
		return pb.JWKType_JWK_TYPE_OCT
	default:
		return pb.JWKType_JWK_TYPE_UNSPECIFIED
	}
}

func KeyUseFromProtobuf(use pb.JWKUse) *KeyUse {
	switch use {
	case pb.JWKUse_JWK_USE_ENC:
		return &KeyUseEnc
	case pb.JWKUse_JWK_USE_SIG:
		return &KeyUseSig
	default:
		return nil
	}
}

func (u *KeyUse) Protobuf() pb.JWKUse {
	if u == nil {
		return pb.JWKUse_JWK_USE_UNSPECIFIED
	}
	switch *u {
	case KeyUseEnc:
		return pb.JWKUse_JWK_USE_ENC
	case KeyUseSig:
		return pb.JWKUse_JWK_USE_SIG
	default:
		return pb.JWKUse_JWK_USE_UNSPECIFIED
	}
}

func KeyOpsFromProtobuf(kops pb.JWKKeyOps) *KeyOps {
	switch kops {
	case pb.JWKKeyOps_JWT_KEY_OPS_SIGN:
		return &KeyOpsSign
	case pb.JWKKeyOps_JWT_KEY_OPS_VERIFY:
		return &KeyOpsVerify
	case pb.JWKKeyOps_JWT_KEY_OPS_ENCRYPT:
		return &KeyOpsEncrypt
	case pb.JWKKeyOps_JWT_KEY_OPS_DECRYPT:
		return &KeyOpsDecrypt
	case pb.JWKKeyOps_JWT_KEY_OPS_WRAP_KEY:
		return &KeyOpsWrapKey
	case pb.JWKKeyOps_JWT_KEY_OPS_UNWRAP_KEY:
		return &KeyOpsUnwrapKey
	case pb.JWKKeyOps_JWT_KEY_OPS_DERIVE_KEY:
		return &KeyOpsDeriveKey
	case pb.JWKKeyOps_JWT_KEY_OPS_DERIVE_BITS:
		return &KeyOpsDeriveBits
	default:
		return nil
	}
}

func (o *KeyOps) Protobuf() pb.JWKKeyOps {
	switch *o {
	case KeyOpsSign:
		return pb.JWKKeyOps_JWT_KEY_OPS_SIGN
	case KeyOpsVerify:
		return pb.JWKKeyOps_JWT_KEY_OPS_VERIFY
	case KeyOpsEncrypt:
		return pb.JWKKeyOps_JWT_KEY_OPS_ENCRYPT
	case KeyOpsDecrypt:
		return pb.JWKKeyOps_JWT_KEY_OPS_DECRYPT
	case KeyOpsWrapKey:
		return pb.JWKKeyOps_JWT_KEY_OPS_WRAP_KEY
	case KeyOpsUnwrapKey:
		return pb.JWKKeyOps_JWT_KEY_OPS_UNWRAP_KEY
	case KeyOpsDeriveKey:
		return pb.JWKKeyOps_JWT_KEY_OPS_DERIVE_KEY
	case KeyOpsDeriveBits:
		return pb.JWKKeyOps_JWT_KEY_OPS_DERIVE_BITS
	default:
		return pb.JWKKeyOps_JWT_KEY_OPS_UNSPECIFIED
	}
}

func (k *JWK) Protobuf() *pb.JWK {
	var keyOps []pb.JWKKeyOps
	for _, v := range k.KeyOps {
		keyOps = append(keyOps, v.Protobuf())
	}

	var x5u *string
	if k.X5u != nil {
		x5uString := k.X5u.String()
		x5u = &x5uString
	}

	crv := pb.ECCurve_EC_CURVE_UNSPECIFIED
	if k.Curve != nil {
		switch *k.Curve {
		case elliptic.P256().Params().Name:
			crv = pb.ECCurve_EC_CURVE_P256
		case elliptic.P384().Params().Name:
			crv = pb.ECCurve_EC_CURVE_P384
		case elliptic.P521().Params().Name:
			crv = pb.ECCurve_EC_CURVE_P521
		}
	}

	return &pb.JWK{
		Kty:      k.Kty.Protobuf(),
		Use:      k.Use.Protobuf(),
		KeyOps:   keyOps,
		Alg:      k.Alg.Protobuf(),
		Kid:      k.Kid,
		X5U:      x5u,
		X5C:      k.X5c,
		X5T:      k.X5t,
		X5T_S256: k.X5tS256,

		K: k.K,

		E: k.E,
		N: k.N,

		D: k.D,

		Dp:  k.Dp,
		Dq:  k.Dq,
		Qi:  k.Qi,
		Crv: crv,
		X:   k.X,
		Y:   k.Y,
	}
}

func JWKFromProtobuf(k *pb.JWK) (*JWK, error) {
	if k == nil {
		return nil, nil
	}

	kty := KeyTypeFromProtobuf(k.GetKty())
	if kty == nil {
		return nil, ErrKeyTypMustBePresent
	}

	keyOps := make([]KeyOps, 0, len(k.GetKeyOps()))
	for _, v := range k.GetKeyOps() {
		kops := KeyOpsFromProtobuf(v)
		if kops != nil {
			keyOps = append(keyOps, *kops)
		}
	}

	var x5u *url.URL
	if k.GetX5U() != "" {
		x5uParsed, err := url.Parse(k.GetX5U())
		if err != nil {
			return nil, err
		}
		x5u = x5uParsed
	}

	var crv *string
	switch k.GetCrv() {
	case pb.ECCurve_EC_CURVE_P256:
		c := elliptic.P256().Params().Name
		crv = &c
	case pb.ECCurve_EC_CURVE_P384:
		c := elliptic.P384().Params().Name
		crv = &c
	case pb.ECCurve_EC_CURVE_P521:
		c := elliptic.P521().Params().Name
		crv = &c
	}

	return &JWK{
		Kty:     *kty,
		Use:     KeyUseFromProtobuf(k.Use),
		KeyOps:  keyOps,
		Alg:     KeyAlgFromProtobuf(k.Alg),
		Kid:     k.Kid,
		X5u:     x5u,
		X5c:     k.X5C,
		X5t:     k.X5T,
		X5tS256: k.X5T_S256,

		K: k.K,

		E: k.E,
		N: k.N,

		D: k.D,

		Dp:    k.Dp,
		Dq:    k.Dq,
		Qi:    k.Qi,
		Curve: crv,
		X:     k.X,
		Y:     k.Y,
	}, nil
}
