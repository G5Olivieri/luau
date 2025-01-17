package clients

import "github.com/google/uuid"

type Client struct {
	ID             string
	RawRedirectURI string
}

var emptyClient *Client

func EmptyClient() Client {
	if emptyClient == nil {
		emptyClient = &Client{
			ID:             uuid.Nil.String(),
			RawRedirectURI: "",
		}
	}
	return *emptyClient
}
