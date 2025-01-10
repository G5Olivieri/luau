package internal

import (
	"context"
	"errors"
	"net/url"

	"github.com/google/uuid"
)

var ErrNotFound = errors.New("not found")

type Client struct {
	ID           uuid.UUID
	Name         map[string]string
	RedirectURIs []url.URL
}

type CreateClientRequest struct {
	Name         map[string]string
	RedirectURIs []url.URL
}

type ClientsService interface {
	Create(context.Context, *CreateClientRequest) (*Client, error)
	Update(context.Context, *Client) (*Client, error)
	DeleteByID(context.Context, *uuid.UUID) error
	GetByID(context.Context, *uuid.UUID) (*Client, error)
}
