package internal

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var ErrNotFound = errors.New("not found")

type User struct {
	ID        uuid.UUID
	Username  string
	Password  string
	LastLogin *time.Time
}

type CreateUserRequest struct {
	Username  string
	Password  string
	LastLogin *time.Time
}

type UsersService interface {
	Create(context.Context, *CreateUserRequest) (*User, error)
	Update(context.Context, *User) (*User, error)
	DeleteByID(context.Context, *uuid.UUID) error
	GetByID(context.Context, *uuid.UUID) (*User, error)
	GetByUsername(context.Context, string) (*User, error)
	GetByUsernamePassword(context.Context, string, string) (*User, error)
	List(context.Context, int, int) ([]*User, error)
}
