package user

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("user not found")

type UserRepository interface {
	GetByUsername(context.Context, string) (*User, error)
	GetByID(context.Context, string) (*User, error)
	Save(context.Context, User) error
}
