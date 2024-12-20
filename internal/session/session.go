package session

import (
	"context"
	"errors"
	"sync"
)

var ErrNotFound = errors.New("NotFound")

type Session struct {
	ID   string
	Data map[string]interface{}
}

type SessionStore interface {
	Save(ctx context.Context, session *Session) error
	Get(ctx context.Context, id string) (*Session, error)
}

type InMemorySessionStore struct {
	sessions map[string]*Session
	mu       sync.Mutex
}

func NewInMemorySessionStore(sessions map[string]*Session) *InMemorySessionStore {
	return &InMemorySessionStore{
		sessions: sessions,
	}
}

func (s *InMemorySessionStore) Save(ctx context.Context, session *Session) error {
	s.mu.Lock()
	s.sessions[session.ID] = session
	s.mu.Unlock()
	return nil
}

func (s *InMemorySessionStore) Get(ctx context.Context, id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	return session, nil
}
