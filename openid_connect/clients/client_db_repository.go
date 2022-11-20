package clients

import (
	"database/sql"
	"net/url"

	"github.com/google/uuid"
)

type ClientDbRepository struct{}

func (r *ClientDbRepository) GetClientById(id uuid.UUID) (Client, error) {
	db, err := sql.Open("sqlite3", "./db/clients.db")
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
	clientSecret := []byte(secret)
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
