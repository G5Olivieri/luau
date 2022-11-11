package openidconnect

import (
	"errors"

	"github.com/google/uuid"
)

func validateClient(id, redirectURI string, repository ClientRepository) (Client, error) {
	clientID, err := uuid.Parse(id)

	if err != nil {
		return Client{}, err
	}

	client, err := repository.GetClientById(clientID)
	if err != nil {
		return client, err
	}

	if client.RedirectURI.String() != redirectURI {
		return Client{}, errors.New("Invalid client")
	}
	return client, nil
}
