package openidconnect

import (
	"crypto/hmac"
	"encoding/base64"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
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

	mac.Reset()
	mac.Write([]byte(request.Csrf))
	expectedCsrf := mac.Sum(nil)

	if !hmac.Equal(csrfChallenge, expectedCsrf) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if err := validateAuthorizationRequest(request.AuthorizationCodeRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = validateClient(request.ClientID, request.RedirectURI, &ClientDummyRepository{})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	if !authenticate(request.Username, request.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "Glayson",
		"aud": request.ClientID,
		"exp": time.Now().Add(5 * time.Second).Unix(),
	})

	tokenString, err := token.SignedString(secret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	uri, err := url.Parse(request.RedirectURI)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	q, _ := url.ParseQuery(uri.RawQuery)
	q.Add("code", tokenString)
	uri.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, uri.String())
}
