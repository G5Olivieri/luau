package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/G5Olivieri/luau/internal/clients"
	"github.com/G5Olivieri/luau/internal/users"
	"github.com/google/uuid"
)

type CodeToCreate struct {
	User                  *users.User
	RedirectURI           string
	Client                *clients.Client
	Nonce                 *string
	CodeChallenge         *string
	CodeChallengeMethod   *string
	AuthenticationMethods *[]string
}

type Code struct {
	ID                    string
	User                  *users.User
	Client                *clients.Client
	RedirectURI           string
	Nonce                 *string
	CodeChallenge         *string
	CodeChallengeMethod   *string
	AuthenticationMethods *[]string
	ExpireAt              int64
	CreatedAt             time.Time
}

var ErrCodeNotFound = errors.New("code not found")

type CodeRepository interface {
	Create(context.Context, *CodeToCreate) (*Code, error)
	GetByID(context.Context, string) (*Code, error)
	Delete(context.Context, *Code) error
}

type InMemoryCodeRepository struct {
	codes     map[string]*Code
	expiresIn time.Duration
}

func NewInMemoryCodeRepository(codes map[string]*Code, expiresIn time.Duration) *InMemoryCodeRepository {
	return &InMemoryCodeRepository{
		codes:     codes,
		expiresIn: expiresIn,
	}
}

func (r *InMemoryCodeRepository) Create(ctx context.Context, toCreate *CodeToCreate) (*Code, error) {
	code := &Code{
		ID:                    uuid.NewString(),
		Client:                toCreate.Client,
		User:                  toCreate.User,
		RedirectURI:           toCreate.RedirectURI,
		CodeChallenge:         toCreate.CodeChallenge,
		CodeChallengeMethod:   toCreate.CodeChallengeMethod,
		Nonce:                 toCreate.Nonce,
		AuthenticationMethods: toCreate.AuthenticationMethods,
		CreatedAt:             time.Now(),
	}
	r.codes[code.ID] = code
	return code, nil
}

func (r *InMemoryCodeRepository) GetByID(ctx context.Context, id string) (*Code, error) {
	v, ok := r.codes[id]
	if !ok {
		return nil, ErrCodeNotFound
	}
	return v, nil
}

func (r *InMemoryCodeRepository) Delete(ctx context.Context, code *Code) error {
	delete(r.codes, code.ID)
	return nil
}
