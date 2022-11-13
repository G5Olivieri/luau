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

var financeSingle *Client
var todoSingle *Client

func newFinanceClient() *Client {
	if financeSingle == nil {
		redirectURI, _ := url.Parse("http://localhost:3000/auth/callback")
		financeID := uuid.MustParse("dd17ceee-9d17-428e-b1f7-31e51cfbb778")
		secret := "j0n8X0T6ALVhnH8qXRMGKoEby6tLyhPr9vkDjKKEoIHlIvBg8dUufXK0Bbh2MSaYDi3YmdSsMmruXwQnrkTZW3tQULvDrAAWPAzMD07PFlsEPRGwMKLt8HpfCqRQpSwlSc6tyOU91IA7jjX3eJra"

		financeSingle = &Client{financeID, []byte(secret), *redirectURI}
	}

	return financeSingle
}

func newTodoClient() *Client {
	if todoSingle == nil {
		redirectURI, _ := url.Parse("http://localhost:3000/auth/callback")
		todoID := uuid.MustParse("a325078a-7baf-4400-95ea-b62a5abdb2e1")
		secret := "x1eqJ953Gg8yNFj7zteKrUXrxFsXaF3yh3UAnJgkfNaC3XWiJgMDnIdaixHTz1FymMWZdc0R"

		todoSingle = &Client{todoID, []byte(secret), *redirectURI}
	}

	return todoSingle
}

func getClientById(id string) *Client {
	finance := newFinanceClient()
	todo := newTodoClient()
	clients := []*Client{finance, todo}

	for _, client := range clients {
		if client.ID.String() == id {
			return client
		}
	}

	return nil
}

func (repository *ClientDummyRepository) GetClientById(id uuid.UUID) (Client, error) {
	client := getClientById(id.String())
	if client == nil {
		return Client{}, errors.New("Client not Found")
	}

	return *client, nil
}
