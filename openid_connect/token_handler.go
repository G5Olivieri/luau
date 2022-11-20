package openidconnect

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gmctechsols/luau/openid_connect/clients"
	"github.com/golang-jwt/jwt/v4"
)

type AccessTokenRequest struct {
	GrantType   string `form:"grant_type"   binding:"required"`
	Code        string `form:"code"         binding:"required"`
	ClientID    string `form:"client_id"    binding:"required"`
	RedirectURI string `form:"redirect_uri" binding:"required"`
}

func validateAccessTokenRequest(request AccessTokenRequest) error {
	if request.GrantType != "authorization_code" {
		return errors.New("Invalid grant_type")
	}

	return nil
}

func TokenHandler(c *gin.Context) {
	var request AccessTokenRequest

	if err := c.ShouldBind(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validateAccessTokenRequest(request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: inject repository
	client, err := validateClient(request.ClientID, request.RedirectURI, &clients.ClientDbRepository{})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	token, err := jwt.Parse(request.Code, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return client.Secret, nil
	})

	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || !token.Valid {
		c.JSON(http.StatusBadGateway, gin.H{"error": "get claims"})
		return
	}

	tokenGenerated := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": claims["sub"],
		"aud": client.ID.String(),
		"iss": issuer,
		"exp": time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
		"iat": time.Now().Unix(),
	})

	tokenString, err := tokenGenerated.SignedString(client.Secret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": tokenString, "expires_in": expiresIn})
}
