package user

import (
	"context"
)

type UserRepository interface {
	GetByUsername(ctx context.Context, username string) (User, error)
	GetByID(ctx context.Context, id string) (User, error)
}
