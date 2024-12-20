package user

import (
	"context"
)

type InMemoryUserRepository struct {
	users map[string]*User
}

func NewInMemoryUserRepository(users map[string]*User) InMemoryUserRepository {
	return InMemoryUserRepository{
		users: users,
	}
}

func (r InMemoryUserRepository) GetByUsername(ctx context.Context, username string) (*User, error) {
	for _, v := range r.users {
		if v.Username == username {
			return v, nil
		}
	}
	return nil, ErrNotFound
}

func (r InMemoryUserRepository) GetByID(ctx context.Context, id string) (*User, error) {
	if u, ok := r.users[id]; ok {
		return u, nil
	}
	return nil, ErrNotFound
}

func (r InMemoryUserRepository) Save(ctx context.Context, user User) error {
	r.users[user.ID] = &user
	return nil
}
