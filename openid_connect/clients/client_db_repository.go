package clients

import (
	"database/sql"
	"encoding/base64"
	"net/url"
	"os"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type ClientDbRepository struct{}

var dbPath = os.Getenv("DATABASE_URL")

func (r *ClientDbRepository) GetClientById(id uuid.UUID) (Client, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return Client{}, err
	}
	defer db.Close()
	if err != nil {
		return Client{}, err
	}

	var (
		client_id    string
		name         string
		secret       string
		redirect_uri string
	)

	err = db.QueryRow("SELECT id, name, secret, redirect_uri FROM clients WHERE id=? LIMIT 1", id.String()).Scan(&client_id, &name, &secret, &redirect_uri)
	if err != nil {
		return Client{}, err
	}

	clientID, err := uuid.Parse(client_id)
	if err != nil {
		return Client{}, err
	}
	// TODO: to cryptograph or use vault
	clientSecret, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return Client{}, err
	}
	redirectURI, err := url.Parse(redirect_uri)
	if err != nil {
		return Client{}, err
	}
	return Client{
		ID:          clientID,
		Secret:      clientSecret,
		RedirectURI: *redirectURI,
	}, nil
}
