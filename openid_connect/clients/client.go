package clients

import (
	"net/url"

	"github.com/google/uuid"
)

type Client struct {
	ID          uuid.UUID
	Secret      []byte
	RedirectURI url.URL
}
