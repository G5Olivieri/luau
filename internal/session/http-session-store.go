package session

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type HTTPSession struct {
	session    *Session
	store      SessionStore
	cookieName string
	expiresIn  time.Duration
}

func NewHttpSession(store SessionStore, cookieName string, expiresIn time.Duration) HTTPSession {
	return HTTPSession{
		store:      store,
		cookieName: cookieName,
		expiresIn:  expiresIn,
	}
}

func (s *HTTPSession) GetFromCookie(ctx context.Context, r *http.Request) (*Session, error) {
	if s.session != nil {
		return s.session, nil
	}

	cookie, err := r.Cookie(s.cookieName)

	if err != nil {
		return nil, err
	}

	session, err := s.store.Get(ctx, cookie.Value)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	s.session = session
	return session, nil
}

func (s *HTTPSession) GetFromCookieOrCreate(ctx context.Context, w http.ResponseWriter, r *http.Request) (*Session, error) {
	if s.session != nil {
		return s.session, nil
	}

	sessionIDCookie, err := r.Cookie(s.cookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return s.create(), nil
	}

	if err != nil {
		return nil, err
	}

	sessionID := sessionIDCookie.Value
	if sessionID == "" {
		return s.create(), nil
	}

	sessionValue, err := s.store.Get(ctx, sessionID)

	if errors.Is(err, ErrNotFound) {
		return s.create(), nil
	}

	if err != nil {
		return nil, err
	}

	s.session = sessionValue
	return sessionValue, err
}

func (s *HTTPSession) create() *Session {
	sessionValue := &Session{
		ID:   uuid.NewString(),
		Data: make(map[string]interface{}),
	}
	s.session = sessionValue
	return sessionValue
}

func (s *HTTPSession) Save(ctx context.Context, session *Session) error {
	return s.store.Save(ctx, session)
}

func (s *HTTPSession) SaveAndSetToCookie(ctx context.Context, w http.ResponseWriter, session *Session) error {
	if err := s.Save(ctx, s.session); err != nil {
		return err
	}
	s.SetToCookie(w, session)
	return nil
}

func (s HTTPSession) SetToCookie(w http.ResponseWriter, session *Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    session.ID,
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Now().Add(s.expiresIn),
	})
}
