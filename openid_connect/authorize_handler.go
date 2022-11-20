package openidconnect

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gmctechsols/luau/openid_connect/clients"
	"github.com/google/uuid"
)

type AuthorizeRequest struct {
	AuthorizationCodeRequest `form:",inline"`
	ClientID                 string `form:"client_id"    binding:"required"`
	RedirectURI              string `form:"redirect_uri" binding:"required"`
	State                    string `form:"state"`
}

func AuthorizeHandler(c *gin.Context) {
	var request AuthorizeRequest
	if err := c.BindQuery(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateAuthorizationRequest(request.AuthorizationCodeRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: inject repository
	_, err := validateClient(request.ClientID, request.RedirectURI, &clients.ClientDbRepository{})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	mac := hmac.New(sha256.New, secret)
	csrf := uuid.New().String()
	mac.Write([]byte(csrf))
	csrfMac := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	c.SetCookie("csrf", csrfMac, 900, "/", "localhost", true, true)
	c.HTML(http.StatusOK, "index.tmpl", gin.H{
		"csrf":         csrf,
		"clientID":     request.ClientID,
		"redirectURI":  request.RedirectURI,
		"responseType": request.ResponseType,
		"scope":        request.Scope,
	})
}
