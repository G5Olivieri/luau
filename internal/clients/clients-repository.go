package clients

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("not found")

type ClientsRepository interface {
	GetByID(ctx context.Context, id string) (*Client, error)
}
