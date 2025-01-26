package adapters

import (
	"github.com/G5Olivieri/luau/kms"
)

func NewGRPCServer(impl kms.KMS) *GRPCServer {
	return &GRPCServer{
		impl: impl,
	}
}
