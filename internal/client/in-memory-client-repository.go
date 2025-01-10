package client

import (
	"context"
)

type InMemoryClientRepository struct {
	clients []*Client
}

func NewInMemoryClientRepository(clients []*Client) InMemoryClientRepository {
	return InMemoryClientRepository{
		clients: clients,
	}
}

func (r InMemoryClientRepository) GetByID(ctx context.Context, id string) (*Client, error) {
	for _, c := range r.clients {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, ErrNotFound
}
