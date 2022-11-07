package openidconnect

import (
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthenticateRequest struct {
	AuthorizationCodeRequest `form:",inline"`
	ClientID                 string `form:"client_id"    binding:"required"`
	RedirectURI              string `form:"redirect_uri" binding:"required"`
	State                    string `form:"state"`
}

func AuthenticateHandler(c *gin.Context) {
	var request AuthenticateRequest
	if err := c.BindQuery(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateAuthorizationRequest(request.AuthorizationCodeRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateClient(request.ClientID, request.RedirectURI, &ClientDummyRepository{}); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	csrf := uuid.New().String()

	mac.Reset()
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