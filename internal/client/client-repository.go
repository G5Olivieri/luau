package client

import (
	"context"
	"errors"
)

var (
	NotFoundErr = errors.New("NotFound")
)

type ClientRepository interface {
	GetByID(ctx context.Context, id string) (Client, error)
}
