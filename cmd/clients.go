package cmd

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
)

func NewClientsCmd() *cobra.Command {
	var (
		secret       string
		name         string
		redirect_uri string
		dbPath       string
	)

	clientsUpdateCmd := &cobra.Command{
		Use:   "update [ID]",
		Short: "update client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			db, err := sql.Open("sqlite3", dbPath)
			if err != nil {
				log.Fatal(err)
			}
			defer db.Close()
			sql := "UPDATE clients SET"
			var stmtArgs []any

			if secret == "" && name == "" && redirect_uri == "" {
				log.Print("None attribute to update was provided")
				return
			}

			if secret != "" {
				sql = fmt.Sprintf("%s secret=?,", sql)
				stmtArgs = append(stmtArgs, secret)
			}
			if name != "" {
				sql = fmt.Sprintf("%s name=?,", sql)
				stmtArgs = append(stmtArgs, name)
			}
			if redirect_uri != "" {
				sql = fmt.Sprintf("%s redirect_uri=?,", sql)
				stmtArgs = append(stmtArgs, redirect_uri)
			}

			sql = fmt.Sprintf("%s WHERE id=?", sql[:len(sql)-1])
			stmtArgs = append(stmtArgs, args[0])

			stmt, err := db.Prepare(sql)
			if err != nil {
				log.Fatal(err)
			}
			defer stmt.Close()
			res, err := stmt.Exec(stmtArgs...)
			if err != nil {
				log.Fatal(err)
			}
			affeted, err := res.RowsAffected()
			if err != nil {
				log.Fatal(err)
			}
			if affeted == 0 {
				log.Printf("%s not found\n", args[0])
				return
			}
			fmt.Printf("{\"id\":\"%s\",\"name\":\"%s\",\"redirect_uri\":\"%s\",\"secret\":\"%s\"}", args[0], name, redirect_uri, secret)
		},
	}

	clientsGetByIdCmd := &cobra.Command{
		Use:   "get [ID]",
		Short: "Get client by ID",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			db, err := sql.Open("sqlite3", dbPath)
			if err != nil {
				log.Fatal(err)
			}
			defer db.Close()
			var (
				id           string
				name         string
				redirect_uri string
				secret       string
			)
			err = db.QueryRow("SELECT id, name, redirect_uri, secret FROM clients WHERE id=?;", args[0]).Scan(&id, &name, &redirect_uri, &secret)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("{\"id\":\"%s\",\"name\":\"%s\",\"redirect_uri\":\"%s\",\"secret\":\"%s\"}", id, name, redirect_uri, secret)
		},
	}

	clientsDeleteCmd := &cobra.Command{
		Use:   "delete [ID]",
		Short: "Delete a client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			db, err := sql.Open("sqlite3", dbPath)
			if err != nil {
				log.Fatal(err)
			}
			defer db.Close()
			stmt, err := db.Prepare("DELETE FROM clients WHERE id=?;")
			if err != nil {
				log.Fatal(err)
			}
			defer stmt.Close()
			res, err := stmt.Exec(args[0])
			if err != nil {
				log.Fatal(err)
			}
			affeted, err := res.RowsAffected()
			if err != nil {
				log.Fatal(err)
			}
			if affeted == 0 {
				log.Println("Not found")
				return
			}
			fmt.Println("Deleted")
		},
	}

	clientsListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all clients",
		Run: func(cmd *cobra.Command, args []string) {
			db, err := sql.Open("sqlite3", dbPath)
			if err != nil {
				log.Fatal(err)
			}
			defer db.Close()
			res, err := db.Query("SELECT id, name, redirect_uri, secret FROM clients;")
			if err != nil {
				log.Fatal(err)
			}
			defer res.Close()
			var buffer bytes.Buffer
			unread := false
			buffer.WriteString("[")
			for res.Next() {
				var (
					id           string
					name         string
					redirect_uri string
					secret       string
				)
				err = res.Scan(&id, &name, &redirect_uri, &secret)
				if err != nil {
					log.Fatal(err)
				}
				buffer.WriteString(fmt.Sprintf("{\"id\":\"%s\",\"name\":\"%s\",\"redirect_uri\":\"%s\",\"secret\":\"%s\"},", id, name, redirect_uri, secret))
				unread = true
			}
			json := buffer.String()
			if unread {
				json = json[:len(json)-1]
			}
			json = json + "]"
			fmt.Print(json)
		},
	}

	clientsCreateCmd := &cobra.Command{
		Use:   "create [NAME] [REDIRECT_URI]",
		Short: "Create a new client",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			db, err := sql.Open("sqlite3", dbPath)
			if err != nil {
				log.Fatal(err)
			}
			defer db.Close()
			stmt, err := db.Prepare("INSERT INTO clients(id, name, redirect_uri, secret) VALUES(?,?,?,?)")
			if err != nil {
				log.Fatal(err)
			}
			defer stmt.Close()
			var secretBytes []byte
			if secret == "" {
				secretBytes = make([]byte, 32)
				_, err = rand.Read(secretBytes)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				secretBytes = []byte(secret)
			}

			secret = base64.StdEncoding.EncodeToString(secretBytes)
			id := uuid.New().String()

			res, err := stmt.Exec(id, args[0], args[1], secret)
			if err != nil {
				log.Fatal(err)
			}

			affected, err := res.RowsAffected()

			if err != nil {
				log.Fatal(err)
			}

			if affected > 0 {
				fmt.Printf("{\"id\":\"%s\",\"name\":\"%s\",\"redirect_uri\":\"%s\",\"secret\":\"%s\"}", id, args[0], args[1], secret)
			}
		},
	}

	clientsCreateCmd.Flags().StringVarP(&secret, "secret", "s", "", "The client secret used to sign JWT and Auth client")

	clientsUpdateCmd.Flags().StringVarP(&name, "name", "n", "", "The client name")
	clientsUpdateCmd.Flags().StringVarP(&secret, "secret", "s", "", "The client secret")
	clientsUpdateCmd.Flags().StringVarP(&redirect_uri, "redirect_uri", "r", "", "The client redirect URI")

	clientsCmd := &cobra.Command{Use: "clients"}
	clientsCmd.AddCommand(clientsCreateCmd)
	clientsCmd.AddCommand(clientsGetByIdCmd)
	clientsCmd.AddCommand(clientsListCmd)
	clientsCmd.AddCommand(clientsUpdateCmd)
	clientsCmd.AddCommand(clientsDeleteCmd)

	clientsCmd.PersistentFlags().StringVar(&dbPath, "db", "./db/luau.db", "The DB path")

	return clientsCmd
}
