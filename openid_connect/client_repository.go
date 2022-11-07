package openidconnect

import (
	"errors"
	"net/url"

	"github.com/google/uuid"
)

type Client struct {
	ID          uuid.UUID
	RedirectURI url.URL
}

type ClientRepository interface {
	GetClientById(id uuid.UUID) (Client, error)
}

type ClientDummyRepository struct{}

func (repository *ClientDummyRepository) GetClientById(id uuid.UUID) (Client, error) {
	if "dd17ceee-9d17-428e-b1f7-31e51cfbb778" != id.String() {
		return Client{}, errors.New("Client not Found")
	}
	redirectURI, err := url.Parse("http://localhost:3000/auth/callback")
	if err != nil {
		return Client{}, err
	}

	return Client{id, *redirectURI}, nil
}
