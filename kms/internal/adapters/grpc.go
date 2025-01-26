package adapters

import (
	"context"
	"errors"

	"github.com/G5Olivieri/luau/jose/jose"
	"github.com/G5Olivieri/luau/jose/jwk"
	"github.com/G5Olivieri/luau/kms"
	pb "github.com/G5Olivieri/luau/kms/kms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type GRPCServer struct {
	impl kms.KMS
	pb.UnimplementedKMSServiceServer
}

func (g *GRPCServer) GenerateKey(ctx context.Context, request *pb.CreateKeyRequest) (*jose.JWK, error) {
	alg := jwk.KeyAlgFromProtobuf(request.GetAlg())
	if alg == nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid alg")
	}

	typ := jwk.KeyTypeFromProtobuf(request.GetKeyType())
	if typ == nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid type")
	}

	use := jwk.KeyUseFromProtobuf(request.GetUse())
	if use == nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid use")
	}

	var keyOps []jwk.KeyOps = make([]jwk.KeyOps, 0, len(request.KeyOps))
	for _, v := range request.KeyOps {
		keyOp := jwk.KeyOpsFromProtobuf(v)
		if keyOp == nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid key ops")
		}
		keyOps = append(keyOps, *keyOp)
	}

	key, err := g.impl.GenerateKey(ctx, kms.KeySpec{
		Alg:    *alg,
		Type:   *typ,
		KeyOps: keyOps,
		Use:    *use,
	})
	if err != nil {
		if errors.Is(err, kms.ErrInvalidKeyOperation) {
			return nil, status.Errorf(codes.InvalidArgument, "generate key: %v", err)
		}
		return nil, status.Errorf(codes.Internal, "generate key: %v", err)
	}

	jwk, err := key.JWK()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "key to jwk: %v", err)
	}
	return jwk.Protobuf(), nil
}

func (g *GRPCServer) GetPublicKey(ctx context.Context, id *wrapperspb.StringValue) (*jose.JWK, error) {
	key, err := g.impl.GetPublicKey(ctx, id.GetValue())
	if err != nil {
		if errors.Is(err, kms.ErrKeyNotFound) {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		return nil, status.Error(codes.Internal, "get public key")
	}
	jwk, err := key.JWK()
	if err != nil {
		return nil, status.Error(codes.Internal, "get public key")
	}

	return jwk.Protobuf(), nil
}

func (g *GRPCServer) Get(ctx context.Context, id *wrapperspb.StringValue) (*jose.JWK, error) {
	key, err := g.impl.Get(ctx, id.GetValue())
	if err != nil {
		if errors.Is(err, kms.ErrKeyNotFound) {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		return nil, status.Errorf(codes.Internal, "get public key: %v", err)
	}

	jwk, err := key.JWK()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get public key: %v", err)
	}

	return jwk.Protobuf(), nil
}

func (g *GRPCServer) Sign(ctx context.Context, request *pb.SignRequest) (*wrapperspb.BytesValue, error) {
	signature, err := g.impl.Sign(ctx, request.GetId(), request.GetMessage())
	if err != nil {
		if errors.Is(err, kms.ErrKeyNotFound) {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		return nil, status.Errorf(codes.Internal, "sign error: %v", err)
	}

	return wrapperspb.Bytes(signature), nil
}

func (g *GRPCServer) Verify(ctx context.Context, request *pb.VerifyRequest) (*wrapperspb.BoolValue, error) {
	valid, err := g.impl.Verify(ctx, request.GetId(), request.GetMessage(), request.GetSignature())
	if err != nil {
		if errors.Is(err, kms.ErrKeyNotFound) {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		return nil, status.Errorf(codes.Internal, "verify error: %v", err)
	}

	return wrapperspb.Bool(valid), nil
}

func (g *GRPCServer) GetPublicKeys(ctx context.Context, request *pb.LimitOffset) (*jose.JWKS, error) {
	keys, err := g.impl.GetPublicKeys(ctx, int(request.GetLimit()), int(request.GetOffset()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get public keys: %v", err)
	}
	jwks := make([]*jose.JWK, 0, len(keys))
	for _, v := range keys {
		jwk, err := v.JWK()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "jwk: %v", err)
		}
		jwks = append(jwks, jwk.Protobuf())
	}
	return &jose.JWKS{
		Jwks: jwks,
	}, nil
}

func (g *GRPCServer) List(ctx context.Context, request *pb.LimitOffset) (*jose.JWKS, error) {
	keys, err := g.impl.List(ctx, int(request.GetLimit()), int(request.GetOffset()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get public keys: %v", err)
	}
	jwks := make([]*jose.JWK, 0, len(keys))
	for _, v := range keys {
		jwk, err := v.JWK()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "jwk: %v", err)
		}
		jwks = append(jwks, jwk.Protobuf())
	}

	return &jose.JWKS{
		Jwks: jwks,
	}, nil
}
