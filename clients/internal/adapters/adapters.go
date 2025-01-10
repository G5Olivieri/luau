package adapters

import (
	"fmt"
	"net/url"

	"github.com/G5Olivieri/luau/clients/internal"
)

func NewGRPCServer(impl internal.ClientsService) *GRPCServer {
	return &GRPCServer{
		impl: impl,
	}
}

func urisStringToURLs(uris []string) ([]url.URL, error) {
	urls := make([]url.URL, 0, len(uris))
	for _, v := range uris {
		parsedUrl, err := url.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("invalid redirect_uri: %v", err)
		}
		urls = append(urls, *parsedUrl)
	}
	return urls, nil
}

func urisURLToStrings(uris []url.URL) []string {
	urls := make([]string, 0, len(uris))
	for _, v := range uris {
		serializedURL := v.String()
		urls = append(urls, serializedURL)
	}
	return urls
}
