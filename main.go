package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

var secret = []byte("SECRET")
var mac = hmac.New(sha256.New, secret)

type Client struct {
  ID uuid.UUID
  RedirectURI url.URL
}

type ClientRepository interface {
  GetClientById(id uuid.UUID) (Client, error)
}

type ClientDummyRepository struct {}

func (repository *ClientDummyRepository) GetClientById(id uuid.UUID) (Client, error) {
  if "dd17ceee-9d17-428e-b1f7-31e51cfbb778" != id.String() {
    return Client{}, errors.New("Client not Found")
  }
  redirectURI, err := url.Parse("http://localhost:3000/auth/callback")
  if err != nil {
    return Client{}, err
  }

  return Client{id, *redirectURI}, nil
}

type AuthorizationCodeRequest struct {
  ResponseType string `form:"response_type" binding:"required"`
  Scope string `form:"scope" binding:"required"`
}

type AuthenticateRequest struct {
  AuthorizationCodeRequest `json:",inline"`
  ClientID string `form:"client_id" binding:"required"`
  RedirectURI string `form:"redirect_uri" binding:"required"`
  State string `form:"state"`
}

type SigninRequest struct {
  AuthorizationCodeRequest `json:",inline"`
  ClientID string `form:"client_id" binding:"required"`
  RedirectURI string `form:"redirect_uri" binding:"required"`
  Username string `form:"username" binding:"required"`
  Password string `form:"password" binding:"required"`
  Csrf string `form:"csrf" binding:"required"`
  State string `form:"state"`
}

func validateRequest(request AuthorizationCodeRequest) error {
  if request.ResponseType != "code" {
    return errors.New("Invalid response_type")
  }

  if !strings.Contains(request.Scope, "openid") {
    return errors.New("Invalid scope")
  }

  return nil
}

func validateClient(id, redirectURI string, repository ClientRepository) error {
  clientID, err := uuid.Parse(id)
  if err != nil {
    return err
  }

  client, err := repository.GetClientById(clientID)
  if err != nil {
    return err
  }

  log.Println(client.RedirectURI.String())
  log.Println(redirectURI)
  if client.RedirectURI.String() != redirectURI {
    return errors.New("Invalid client")
  }
  return nil
}

func authenticate(username, password string) bool {
  return username == "Glayson" && password == "Murollo"
}


func main() {
	r := gin.Default()
  r.LoadHTMLGlob("templates/*")

	r.GET("/authenticate", func(c *gin.Context) {
    var request AuthenticateRequest
    if err := c.BindQuery(&request); err != nil {
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      return
    }
    if err := validateRequest(request.AuthorizationCodeRequest); err != nil {
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      return
    }
    if err := validateClient(request.ClientID, request.RedirectURI, &ClientDummyRepository{}); err != nil {
      c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
      return
    }

    csrf := uuid.New().String()

    mac.Write([]byte(csrf))
    csrfMac := base64.URLEncoding.EncodeToString(mac.Sum(nil))

    c.SetCookie("csrf", csrfMac, 900, "/", "localhost", true, true)
    c.HTML(http.StatusOK, "index.tmpl", gin.H{
      "csrf": csrf,
      "clientID": request.ClientID,
      "redirectURI": request.RedirectURI,
      "responseType": request.ResponseType,
      "scope": request.Scope,
    })
	})

  r.POST("/signin", func(c *gin.Context) {
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

    mac.Write([]byte(request.Csrf))
    expectedCsrf := mac.Sum(nil)

    if !hmac.Equal(csrfChallenge, expectedCsrf) {
      c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
      return
    }

    if err := validateRequest(request.AuthorizationCodeRequest); err != nil {
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
  })
	r.Run()
}
