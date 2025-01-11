package internal

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
)

var (
	ErrInvalidLimitOffset = errors.New("invalid limit or offset")
)

type InMemoryClientsService struct {
	clients map[uuid.UUID]*Client
	mutex   sync.RWMutex
}

func NewInMemoryClientsService() *InMemoryClientsService {
	return &InMemoryClientsService{
		clients: make(map[uuid.UUID]*Client),
		mutex:   sync.RWMutex{},
	}
}

func (s *InMemoryClientsService) Create(_ context.Context, request *CreateClientRequest) (*Client, error) {
	id := uuid.New()
	client := &Client{
		ID:           id,
		Name:         request.Name,
		RedirectURIs: request.RedirectURIs,
	}
	s.mutex.Lock()
	s.clients[id] = client
	s.mutex.Unlock()

	return client, nil
}

func (s *InMemoryClientsService) Update(_ context.Context, request *Client) (*Client, error) {
	s.mutex.RLock()
	client, ok := s.clients[request.ID]
	s.mutex.RUnlock()

	if !ok {
		return nil, ErrNotFound
	}

	client.Name = request.Name
	client.RedirectURIs = request.RedirectURIs

	return client, nil
}

func (s *InMemoryClientsService) DeleteByID(_ context.Context, id *uuid.UUID) error {
	s.mutex.RLock()
	_, ok := s.clients[*id]
	s.mutex.RUnlock()
	if !ok {
		return ErrNotFound
	}

	s.mutex.Lock()
	delete(s.clients, *id)
	s.mutex.Unlock()

	return nil
}

func (s *InMemoryClientsService) GetByID(_ context.Context, id *uuid.UUID) (*Client, error) {
	s.mutex.RLock()
	client, ok := s.clients[*id]
	s.mutex.RUnlock()

	if !ok {
		return nil, ErrNotFound
	}

	return client, nil
}

func (s *InMemoryClientsService) List(_ context.Context, limit int, offset int) ([]*Client, error) {
	if limit < 0 || offset < 0 {
		return nil, ErrInvalidLimitOffset
	}

	if limit == 0 {
		return make([]*Client, 0), nil
	}

	if limit > 1024 {
		limit = 1024
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()
	clientLen := len(s.clients)
	if offset > clientLen {
		return make([]*Client, 0), nil
	}
	response := make([]*Client, 0, min(limit, clientLen-offset))
	countOffset := 0
	countLimit := 0
	for _, v := range s.clients {
		countOffset += 1
		if countOffset >= offset {
			response = append(response, v)
			countLimit += 1
			if countLimit == limit {
				break
			}
		}
	}

	return response, nil
}
