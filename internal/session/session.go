package session

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("NotFound")

type Session struct {
	ID   string
	Data map[string]interface{}
}

type SessionStore interface {
	Set(ctx context.Context, session *Session) error
	Get(ctx context.Context, id string) (*Session, error)
}

type InMemorySessionStore struct {
	sessions map[string]*Session
}

func NewInMemorySessionStore(sessions map[string]*Session) InMemorySessionStore {
	return InMemorySessionStore{
		sessions: sessions,
	}
}

func (s InMemorySessionStore) Set(ctx context.Context, session *Session) error {
	s.sessions[session.ID] = session
	return nil
}

func (s InMemorySessionStore) Get(ctx context.Context, id string) (*Session, error) {
	session, ok := s.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	return session, nil
}
