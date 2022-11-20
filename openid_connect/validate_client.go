package openidconnect

import (
	"errors"

	"github.com/gmctechsols/luau/openid_connect/clients"
	"github.com/google/uuid"
)

func validateClient(id, redirectURI string, repository clients.ClientRepository) (clients.Client, error) {
	clientID, err := uuid.Parse(id)

	if err != nil {
		return clients.Client{}, err
	}

	client, err := repository.GetClientById(clientID)
	if err != nil {
		return client, err
	}

	if client.RedirectURI.String() != redirectURI {
		return clients.Client{}, errors.New("Invalid client")
	}
	return client, nil
}
