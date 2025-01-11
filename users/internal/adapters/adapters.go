package adapters

import (
	"github.com/G5Olivieri/luau/users/internal"
)

func NewGRPCServer(impl internal.UsersService) *GRPCServer {
	return &GRPCServer{
		impl: impl,
	}
}
