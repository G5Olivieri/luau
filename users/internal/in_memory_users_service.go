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

type InMemoryUsersService struct {
	users  map[uuid.UUID]*User
	mutex  sync.RWMutex
	hasher PasswordHasher
}

func NewInMemoryUsersService(hasher PasswordHasher) *InMemoryUsersService {
	return &InMemoryUsersService{
		users:  make(map[uuid.UUID]*User),
		mutex:  sync.RWMutex{},
		hasher: hasher,
	}
}

func (s *InMemoryUsersService) Create(_ context.Context, request *CreateUserRequest) (*User, error) {
	hash, err := s.hasher.Hash(request.Password)

	if err != nil {
		return nil, err
	}

	id := uuid.New()
	user := &User{
		ID:        id,
		Username:  request.Username,
		Password:  hash,
		LastLogin: request.LastLogin,
	}
	s.mutex.Lock()
	s.users[id] = user
	s.mutex.Unlock()

	return user, nil
}

func (s *InMemoryUsersService) Update(_ context.Context, request *User) (*User, error) {
	s.mutex.RLock()
	user, ok := s.users[request.ID]
	s.mutex.RUnlock()

	if !ok {
		return nil, ErrNotFound
	}

	user.Username = request.Username
	user.Password = request.Password
	user.LastLogin = request.LastLogin

	return user, nil
}

func (s *InMemoryUsersService) DeleteByID(_ context.Context, id *uuid.UUID) error {
	s.mutex.RLock()
	_, ok := s.users[*id]
	s.mutex.RUnlock()
	if !ok {
		return ErrNotFound
	}

	s.mutex.Lock()
	delete(s.users, *id)
	s.mutex.Unlock()

	return nil
}

func (s *InMemoryUsersService) GetByUsername(_ context.Context, username string) (*User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, v := range s.users {
		if v.Username == username {
			return v, nil
		}
	}

	return nil, ErrNotFound
}

func (s *InMemoryUsersService) GetByUsernamePassword(_ context.Context, username, password string) (*User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, v := range s.users {
		if v.Username == username {
			verified, err := s.hasher.Verify(password, v.Password)

			if err != nil {
				return nil, err
			}

			if !verified {
				return nil, ErrNotFound
			}

			return v, nil
		}
	}

	return nil, ErrNotFound
}

func (s *InMemoryUsersService) GetByID(_ context.Context, id *uuid.UUID) (*User, error) {
	s.mutex.RLock()
	user, ok := s.users[*id]
	s.mutex.RUnlock()

	if !ok {
		return nil, ErrNotFound
	}

	return user, nil
}

func (s *InMemoryUsersService) List(_ context.Context, limit int, offset int) ([]*User, error) {
	if limit < 0 || offset < 0 {
		return nil, ErrInvalidLimitOffset
	}

	if limit == 0 {
		return make([]*User, 0), nil
	}

	if limit > 1024 {
		limit = 1024
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()
	userLen := len(s.users)
	if offset > userLen {
		return make([]*User, 0), nil
	}
	response := make([]*User, 0, min(limit, userLen-offset))
	countOffset := 0
	countLimit := 0
	for _, v := range s.users {
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
