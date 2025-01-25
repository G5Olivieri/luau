package adapters

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"

	"github.com/G5Olivieri/luau/clients/internal"
)

type createClient struct {
	Name         map[string]string `json:"name"`
	RedirectURIs []string          `json:"redirectUris"`
}

type createdClient struct {
	ID           string            `json:"id"`
	Name         map[string]string `json:"name"`
	RedirectURIs []string          `json:"redirectUris"`
	Secret       string            `json:"secret"`
}

func CreateFromJson(impl internal.ClientsService, clientPath string) (string, error) {
	initialClientContent, err := os.ReadFile(clientPath)
	if err != nil {
		return "", nil
	}

	var initialClient createClient
	if err = json.Unmarshal(initialClientContent, &initialClient); err != nil {
		return "", nil
	}

	redirectUris := make([]url.URL, 0, len(initialClient.RedirectURIs))
	for _, v := range initialClient.RedirectURIs {
		redirect, err := url.Parse(v)
		if err != nil {
			return "", err
		}
		redirectUris = append(redirectUris, *redirect)
	}

	client, err := impl.Create(context.Background(), &internal.CreateClientRequest{
		Name:         initialClient.Name,
		RedirectURIs: redirectUris,
	})

	if err != nil {
		return "", nil
	}

	created := createdClient{
		ID:           client.ID.String(),
		Name:         client.Name,
		RedirectURIs: initialClient.RedirectURIs,
		Secret:       base64.StdEncoding.EncodeToString(client.Secret),
	}

	createdJSON, err := json.Marshal(created)
	if err != nil {
		return "", nil
	}

	return string(createdJSON), nil
}
