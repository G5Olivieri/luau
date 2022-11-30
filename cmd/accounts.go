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
	"golang.org/x/crypto/argon2"
)

func NewAccountsCmd() *cobra.Command {
	var (
		username string
		password string
		dbPath   string
	)

	accountsUpdateCmd := &cobra.Command{
		Use:   "update [ID]",
		Short: "update account",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if username == "" && password == "" {
				log.Println("None attribute to update was provided")
				return
			}
			db, err := sql.Open("sqlite3", dbPath)
			if err != nil {
				log.Fatal(err)
			}
			defer db.Close()
			sql := "UPDATE accounts SET"
			var stmtArgs []any

			if password != "" {
				sql = fmt.Sprintf("%s password=?, salt=?,", sql)
				salt := make([]byte, 256)
				_, err = rand.Read(salt)
				if err != nil {
					log.Fatal(err)
				}
				password = base64.StdEncoding.EncodeToString(argon2.IDKey([]byte(password), salt, 2, 15*1024, 1, 32))
				stmtArgs = append(stmtArgs, password)
				stmtArgs = append(stmtArgs, base64.StdEncoding.EncodeToString(salt))
			}
			if username != "" {
				sql = fmt.Sprintf("%s username=?,", sql)
				stmtArgs = append(stmtArgs, username)
			}

			sql = fmt.Sprintf("%s WHERE id=? RETURNING username", sql[:len(sql)-1])
			stmtArgs = append(stmtArgs, args[0])

			stmt, err := db.Prepare(sql)
			if err != nil {
				log.Fatal(err)
			}
			defer stmt.Close()
			err = stmt.QueryRow(stmtArgs...).Scan(&username)
			if err != nil {
				log.Fatal(err)
			}
			if username == "" {
				log.Printf("%s not found\n", args[0])
				return
			}
			fmt.Printf("{\"id\":\"%s\",\"username\":\"%s\"}", args[0], username)
		},
	}

	accountsGetByIdCmd := &cobra.Command{
		Use:   "get [ID]",
		Short: "Get account by ID",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			db, err := sql.Open("sqlite3", dbPath)
			if err != nil {
				log.Fatal(err)
			}
			defer db.Close()
			err = db.QueryRow("SELECT username FROM accounts WHERE id=?;", args[0]).Scan(&username)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("{\"id\":\"%s\",\"username\":\"%s\"}", args[0], username)
		},
	}

	accountsDeleteCmd := &cobra.Command{
		Use:   "delete [ID]",
		Short: "Delete a account",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			db, err := sql.Open("sqlite3", dbPath)
			if err != nil {
				log.Fatal(err)
			}
			defer db.Close()
			stmt, err := db.Prepare("DELETE FROM accounts WHERE id=?;")
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
		},
	}

	accountsListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all accounts",
		Run: func(cmd *cobra.Command, args []string) {
			db, err := sql.Open("sqlite3", dbPath)
			if err != nil {
				log.Fatal(err)
			}
			defer db.Close()
			res, err := db.Query("SELECT id, username, password FROM accounts;")
			if err != nil {
				log.Fatal(err)
			}
			defer res.Close()
			var buffer bytes.Buffer
			unread := false
			buffer.WriteString("[")
			for res.Next() {
				var id string

				err = res.Scan(&id, &username, &password)
				if err != nil {
					log.Fatal(err)
				}
				buffer.WriteString(fmt.Sprintf("{\"id\":\"%s\",\"username\":\"%s\"}", id, username))
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

	accountsCreateCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new account",
		Run: func(cmd *cobra.Command, args []string) {
			db, err := sql.Open("sqlite3", dbPath)
			if err != nil {
				log.Fatal(err)
			}
			defer db.Close()
			stmt, err := db.Prepare("INSERT INTO accounts(id, username, password, salt) VALUES(?,?,?,?)")
			if err != nil {
				log.Fatal(err)
			}
			defer stmt.Close()

			id := uuid.New().String()
			salt := make([]byte, 256)
			_, err = rand.Read(salt)
			if err != nil {
				log.Fatal(err)
			}
			password = base64.StdEncoding.EncodeToString(argon2.IDKey([]byte(password), salt, 2, 15*1024, 1, 32))
			res, err := stmt.Exec(id, username, password, base64.StdEncoding.EncodeToString(salt))
			if err != nil {
				log.Fatal(err)
			}

			affected, err := res.RowsAffected()

			if err != nil {
				log.Fatal(err)
			}

			if affected > 0 {
				fmt.Printf("{\"id\":\"%s\",\"username\":\"%s\"}", id, username)
			}
		},
	}

	accountsCreateCmd.Flags().StringVarP(&username, "username", "u", "", "The username")
	accountsCreateCmd.Flags().StringVarP(&password, "password", "p", "", "The password")
	accountsCreateCmd.MarkFlagRequired("username")
	accountsCreateCmd.MarkFlagRequired("password")

	accountsUpdateCmd.Flags().StringVarP(&username, "username", "u", "", "The username")
	accountsUpdateCmd.Flags().StringVarP(&password, "password", "p", "", "The password")

	accountsCmd := &cobra.Command{Use: "accounts"}
	accountsCmd.AddCommand(accountsCreateCmd)
	accountsCmd.AddCommand(accountsGetByIdCmd)
	accountsCmd.AddCommand(accountsListCmd)
	accountsCmd.AddCommand(accountsUpdateCmd)
	accountsCmd.AddCommand(accountsDeleteCmd)

	accountsCmd.PersistentFlags().StringVar(&dbPath, "db", "./db/luau.db", "The DB path")

	return accountsCmd
}
