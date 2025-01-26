package kms

import (
	"context"

	"github.com/G5Olivieri/luau/jose/jose"
	"github.com/G5Olivieri/luau/jose/jwk"
	"github.com/G5Olivieri/luau/kms"
	kmsjwk "github.com/G5Olivieri/luau/kms/jwk"
	pb "github.com/G5Olivieri/luau/kms/kms"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type KMSGrpcClient struct {
	grpcClient pb.KMSServiceClient
}

func NewGRPCClientsRepository(conn *grpc.ClientConn) *KMSGrpcClient {
	clientServiceClient := pb.NewKMSServiceClient(conn)
	return &KMSGrpcClient{
		grpcClient: clientServiceClient,
	}
}

func (g *KMSGrpcClient) GenerateKey(ctx context.Context, spec kms.KeySpec) (kms.Key, error) {
	keyOps := make([]jose.JWKKeyOps, 0, len(spec.KeyOps))
	for _, v := range spec.KeyOps {
		kops := v.Protobuf()
		keyOps = append(keyOps, kops)
	}
	pbKey, err := g.grpcClient.GenerateKey(ctx, &pb.CreateKeyRequest{
		Alg:     spec.Alg.Protobuf(),
		KeyType: spec.Type.Protobuf(),
		Use:     spec.Use.Protobuf(),
		KeyOps:  keyOps,
	})
	if err != nil {
		return nil, err
	}
	jwkvalue, err := jwk.JWKFromProtobuf(pbKey)

	if err != nil {
		return nil, err
	}

	return kmsjwk.KeyFromJWK(jwkvalue)
}

func (g *KMSGrpcClient) GetPublicKey(ctx context.Context, id string) (kms.Key, error) {
	pbJwk, err := g.grpcClient.GetPublicKey(ctx, wrapperspb.String(id))

	if err != nil {
		return nil, err
	}
	jwkvalue, err := jwk.JWKFromProtobuf(pbJwk)

	if err != nil {
		return nil, err
	}

	return kmsjwk.KeyFromJWK(jwkvalue)
}

func (g *KMSGrpcClient) Get(ctx context.Context, id string) (kms.Key, error) {
	pbJwk, err := g.grpcClient.Get(ctx, wrapperspb.String(id))

	if err != nil {
		return nil, err
	}
	jwkvalue, err := jwk.JWKFromProtobuf(pbJwk)

	if err != nil {
		return nil, err
	}

	return kmsjwk.KeyFromJWK(jwkvalue)
}

func (g *KMSGrpcClient) GetPublicKeys(ctx context.Context, limit, offset int) ([]kms.Key, error) {
	pbJwks, err := g.grpcClient.GetPublicKeys(ctx, &pb.LimitOffset{
		Limit:  int32(limit),
		Offset: int32(offset),
	})

	if err != nil {
		return nil, err
	}
	jwks := make([]kms.Key, 0, len(pbJwks.Jwks))
	for _, v := range pbJwks.Jwks {
		jwkvalue, err := jwk.JWKFromProtobuf(v)
		if err != nil {
			return nil, err
		}
		key, err := kmsjwk.KeyFromJWK(jwkvalue)

		if err != nil {
			return nil, err
		}

		jwks = append(jwks, key)
	}
	return jwks, nil
}

func (g *KMSGrpcClient) List(ctx context.Context, limit, offset int) ([]kms.Key, error) {
	pbJwks, err := g.grpcClient.List(ctx, &pb.LimitOffset{
		Limit:  int32(limit),
		Offset: int32(offset),
	})

	if err != nil {
		return nil, err
	}

	jwks := make([]kms.Key, 0, len(pbJwks.Jwks))
	for _, v := range pbJwks.Jwks {
		jwkvalue, err := jwk.JWKFromProtobuf(v)
		if err != nil {
			return nil, err
		}
		key, err := kmsjwk.KeyFromJWK(jwkvalue)

		if err != nil {
			return nil, err
		}

		jwks = append(jwks, key)
	}

	return jwks, nil
}

func (g *KMSGrpcClient) Sign(ctx context.Context, id string, message []byte) ([]byte, error) {
	r, err := g.grpcClient.Sign(ctx, &pb.SignRequest{
		Id:      id,
		Message: message,
	})
	if err != nil {
		return nil, err
	}

	return r.GetValue(), nil
}

func (g *KMSGrpcClient) Verify(ctx context.Context, id string, message, signature []byte) (bool, error) {
	r, err := g.grpcClient.Verify(ctx, &pb.VerifyRequest{
		Id:        id,
		Message:   message,
		Signature: signature,
	})

	if err != nil {
		return false, err
	}

	return r.GetValue(), nil
}
