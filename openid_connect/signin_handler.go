package openidconnect

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gmctechsols/luau/openid_connect/clients"
	"github.com/golang-jwt/jwt/v4"
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

// TODO: validate from database
// TODO: hash password
func authenticate(username, password string) bool {
	return username == "Glayson" && password == "Murollo"
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

	if !authenticate(request.Username, request.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		// TODO: fetch from database
		"sub": "Glayson",
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
	c.Redirect(http.StatusFound, uri.String())
}
