package clients

import (
	"context"
)

type InMemoryClientsRepository struct {
	clients []*Client
}

func NewInMemoryClientsRepository(clients []*Client) InMemoryClientsRepository {
	return InMemoryClientsRepository{
		clients: clients,
	}
}

func (r InMemoryClientsRepository) GetByID(ctx context.Context, id string) (*Client, error) {
	for _, c := range r.clients {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, ErrNotFound
}
