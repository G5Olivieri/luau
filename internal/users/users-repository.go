package users

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("user not found")

type UsersRepository interface {
	GetByUsername(context.Context, string) (*User, error)
	GetByUsernamePassword(context.Context, string, string) (*User, error)
	GetByID(context.Context, string) (*User, error)
	Update(context.Context, *User) (*User, error)
}
