package openidconnect

import (
	"errors"
	"net/url"

	"github.com/google/uuid"
)

type Client struct {
	ID          uuid.UUID
	Secret      []byte
	RedirectURI url.URL
}

type ClientRepository interface {
	GetClientById(id uuid.UUID) (Client, error)
}

// TODO: create a ClientDatabaseRepository
type ClientDummyRepository struct{}

var finance_single *Client

func newFinanceClient() *Client {
	if finance_single == nil {
		redirectURI, _ := url.Parse("http://localhost:3000/auth/callback")
		finance_id := uuid.MustParse("dd17ceee-9d17-428e-b1f7-31e51cfbb778")
		secret := "j0n8X0T6ALVhnH8qXRMGKoEby6tLyhPr9vkDjKKEoIHlIvBg8dUufXK0Bbh2MSaYDi3YmdSsMmruXwQnrkTZW3tQULvDrAAWPAzMD07PFlsEPRGwMKLt8HpfCqRQpSwlSc6tyOU91IA7jjX3eJra"

		finance_single = &Client{finance_id, []byte(secret), *redirectURI}
	}

	return finance_single
}

func (repository *ClientDummyRepository) GetClientById(id uuid.UUID) (Client, error) {
	finance := newFinanceClient()

	if finance.ID.String() != id.String() {
		return Client{}, errors.New("Client not Found")
	}

	return *finance, nil
}
