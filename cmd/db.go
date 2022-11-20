package cmd

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
)

func removeDB() {
	log.Println("Removing file ./db/clients.db")
	os.Remove("./db/clients.db")
}

func createDB() {
	log.Println("Opening file ./db/clients.db")
	db, err := sql.Open("sqlite3", "./db/clients.db")
	if err != nil {
		log.Fatal(err)
	}
	sql := `
    CREATE TABLE IF NOT EXISTS clients(
      id TEXT PRIMARY KEY,
      name TEXT,
      secret TEXT,
      redirect_uri TEXT
    );
    CREATE TABLE IF NOT EXISTS accounts(
      id TEXT PRIMARY KEY,
      username TEXT,
      password TEXT,
    );
  `
	log.Println("Creating clients table")
	_, err = db.Exec(sql)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Closing file ./db/clients.db")
	db.Close()
}

func NewDbCmd() *cobra.Command {
	dbDeleteCmd := &cobra.Command{
		Use: "delete",
		Run: func(cmd *cobra.Command, args []string) {
			removeDB()
		},
	}
	dbCreateCmd := &cobra.Command{
		Use: "create",
		Run: func(cmd *cobra.Command, args []string) {
			createDB()
		},
	}
	dbCmd := &cobra.Command{Use: "db"}
	dbCmd.AddCommand(dbDeleteCmd)
	dbCmd.AddCommand(dbCreateCmd)
	return dbCmd
}
