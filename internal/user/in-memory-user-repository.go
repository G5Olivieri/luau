package user

import (
	"context"
	"fmt"
)

type InMemoryUserRepository struct {
	users []User
}

func NewInMemoryUserRepository(users []User) InMemoryUserRepository {
	return InMemoryUserRepository{
		users: users,
	}
}

func (r InMemoryUserRepository) GetByUsername(ctx context.Context, username string) (User, error) {
	for _, u := range r.users {
		if u.Username == username {
			return u, nil
		}
	}
	return EmptyUser(), fmt.Errorf("Client not found")
}

func (r InMemoryUserRepository) GetByID(ctx context.Context, id string) (User, error) {
	for _, u := range r.users {
		if u.ID == id {
			return u, nil
		}
	}
	return EmptyUser(), fmt.Errorf("Client not found")
}
