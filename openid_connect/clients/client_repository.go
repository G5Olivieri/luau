package clients

import (
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type ClientRepository interface {
	GetClientById(id uuid.UUID) (Client, error)
}
