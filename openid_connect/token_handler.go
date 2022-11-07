package openidconnect

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
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

	err := validateClient(request.ClientID, request.RedirectURI, &ClientDummyRepository{})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	token, err := jwt.Parse(request.Code, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil
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
		"aud": request.ClientID,
		"iss": "https://luau.com",
		"exp": time.Now().Add(30 * time.Minute).Unix(),
	})

	tokenString, err := tokenGenerated.SignedString(secret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": tokenString, "expires_in": 1800})
}
