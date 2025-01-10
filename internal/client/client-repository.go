package client

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("not found")

type ClientRepository interface {
	GetByID(ctx context.Context, id string) (*Client, error)
}
