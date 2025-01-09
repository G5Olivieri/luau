package internal

import (
	"context"

	"github.com/google/uuid"
)

type InMemoryClientsService struct {
	clients map[uuid.UUID]*Client
}

func NewInMemoryClientsService() *InMemoryClientsService {
	return &InMemoryClientsService{
		clients: make(map[uuid.UUID]*Client),
	}
}

func (s *InMemoryClientsService) Create(_ context.Context, request *CreateClientRequest) (*Client, error) {
	id := uuid.New()
	client := &Client{
		ID:           id,
		Name:         request.Name,
		RedirectURIs: request.RedirectURIs,
	}
	s.clients[id] = client

	return client, nil
}

func (s *InMemoryClientsService) Update(_ context.Context, request *Client) (*Client, error) {
	client, ok := s.clients[request.ID]

	if !ok {
		return nil, ErrNotFound
	}

	client.Name = request.Name
	client.RedirectURIs = request.RedirectURIs

	return client, nil
}

func (s *InMemoryClientsService) DeleteByID(_ context.Context, id *uuid.UUID) error {
	_, ok := s.clients[*id]

	if !ok {
		return ErrNotFound
	}

	delete(s.clients, *id)

	return nil
}

func (s *InMemoryClientsService) GetByID(_ context.Context, id *uuid.UUID) (*Client, error) {
	client, ok := s.clients[*id]

	if !ok {
		return nil, ErrNotFound
	}

	return client, nil
}
