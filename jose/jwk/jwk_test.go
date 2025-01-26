package jwk_test

import (
	"testing"

	pb "github.com/G5Olivieri/luau/jose/jose"
	"github.com/G5Olivieri/luau/jose/jwk"
)

func TestAlgNil(t *testing.T) {
	alg := jwk.KeyAlgFromProtobuf(pb.JWKAlg_JWK_ALG_UNSPECIFIED)
	if alg != nil {
		t.Fatalf("alg is not nil alg is %v", alg)
	}
}

func TestAlgIsNotNil(t *testing.T) {
	alg := jwk.KeyAlgFromProtobuf(pb.JWKAlg_JWK_ALG_HS256)
	if alg == nil {
		t.Fatalf("alg is nil %v", alg)
	}
}
