package cmd

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
)

func removeDB(dbPath string) {
	log.Printf("Removing file %s\n", dbPath)
	os.Remove(dbPath)
}

func createDB(dbPath string) {
	log.Printf("Opening file %s\n", dbPath)
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
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
      salt TEXT
    );
  `
	log.Println("Creating tables")
	_, err = db.Exec(sql)
	if err != nil {
		log.Fatal(err)
	}
}

func NewDbCmd() *cobra.Command {
	var dbPath string

	dbDeleteCmd := &cobra.Command{
		Use: "delete",
		Run: func(cmd *cobra.Command, args []string) {
			removeDB(dbPath)
		},
	}
	dbCreateCmd := &cobra.Command{
		Use: "create",
		Run: func(cmd *cobra.Command, args []string) {
			createDB(dbPath)
		},
	}
	dbCmd := &cobra.Command{Use: "db"}
	dbCmd.AddCommand(dbDeleteCmd)
	dbCmd.AddCommand(dbCreateCmd)

	dbCmd.PersistentFlags().StringVar(&dbPath, "db", "./db/luau.db", "The DB path")

	return dbCmd
}
