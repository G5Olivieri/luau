package openidconnect

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gmctechsols/luau/openid_connect/clients"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
)

type SigninRequest struct {
	AuthorizationCodeRequest `form:",inline"`
	ClientID                 string `form:"client_id"    binding:"required"`
	RedirectURI              string `form:"redirect_uri" binding:"required"`
	Username                 string `form:"username"     binding:"required"`
	Password                 string `form:"password"     binding:"required"`
	Csrf                     string `form:"csrf"         binding:"required"`
	State                    string `form:"state"`
}

var dbPath = os.Getenv("DATABASE_URL")

func registerSession(client clients.Client, username string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	stmt, err := db.Prepare("INSERT INTO sessions(id, client, username, created_at) VALUES(?,?,?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(uuid.New().String(), client.ID.String(), username, time.Now().Unix())
	if err != nil {
		return err
	}

	return nil
}

func authenticate(username, password string) (bool, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return false, err
	}
	defer db.Close()

	var (
		dbPassword, dbSalt string
	)
	err = db.QueryRow("SELECT password, salt FROM accounts WHERE username=?;", username).Scan(&dbPassword, &dbSalt)
	if err != nil {
		return false, err
	}

	salt, err := base64.StdEncoding.DecodeString(dbSalt)
	if err != nil {
		return false, err
	}
	pwdBytes, err := base64.StdEncoding.DecodeString(dbPassword)
	if err != nil {
		return false, err
	}
	providedPwd := argon2.IDKey([]byte(password), salt, 2, 15*1024, 1, 32)
	return subtle.ConstantTimeCompare(providedPwd, pwdBytes) == 1, nil
}

func SiginHandler(c *gin.Context) {
	var request SigninRequest
	if err := c.ShouldBind(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	csrfEncoded, err := c.Cookie("csrf")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	csrfChallenge, err := base64.URLEncoding.DecodeString(csrfEncoded)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(request.Csrf))
	expectedCsrf := mac.Sum(nil)

	if !hmac.Equal(csrfChallenge, expectedCsrf) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// TODO: inject repository
	client, err := validateClient(request.ClientID, request.RedirectURI, &clients.ClientDbRepository{})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	authenticated, err := authenticate(request.Username, request.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !authenticated {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": request.Username,
		"aud": request.ClientID,
		"exp": time.Now().Add(5 * time.Second).Unix(),
	})

	tokenString, err := token.SignedString(client.Secret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	uri := client.RedirectURI
	q, _ := url.ParseQuery(uri.RawQuery)
	q.Add("code", tokenString)
	uri.RawQuery = q.Encode()

	err = registerSession(client, request.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.Redirect(http.StatusFound, uri.String())
}
