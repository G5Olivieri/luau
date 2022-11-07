package openidconnect

import (
	"errors"

	"github.com/google/uuid"
)

func validateClient(id, redirectURI string, repository ClientRepository) error {
	clientID, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	client, err := repository.GetClientById(clientID)
	if err != nil {
		return err
	}

	if client.RedirectURI.String() != redirectURI {
		return errors.New("Invalid client")
	}
	return nil
}
