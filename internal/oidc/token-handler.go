package oidc

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/G5Olivieri/luau/internal/client"
	luaujwt "github.com/G5Olivieri/luau/internal/jwt"
	"github.com/G5Olivieri/luau/internal/user"
	"github.com/julienschmidt/httprouter"
)

type TokenHandlerResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    uint32 `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

type TokenHandler struct {
	clientRepository         client.ClientRepository
	authorizationCodeEncoder AuthorizationCodeEncoder
	userRepository           user.UserRepository
	idTokenJWTEncoder        IDTokenJWTEncoder
	expiration               int64
	internalJWT              luaujwt.JWTEncoder
}

func NewTokenHandler(
	clientRepository client.ClientRepository,
	authorizationCodeEncoder AuthorizationCodeEncoder,
	idTokenJWTEncoder IDTokenJWTEncoder,
	userRepository user.UserRepository,
	expiration int64,
	internalJWT luaujwt.JWTEncoder,
) TokenHandler {
	return TokenHandler{
		clientRepository:         clientRepository,
		authorizationCodeEncoder: authorizationCodeEncoder,
		userRepository:           userRepository,
		idTokenJWTEncoder:        idTokenJWTEncoder,
		expiration:               expiration,
		internalJWT:              internalJWT,
	}
}

func (h TokenHandler) Handle(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	err := r.ParseForm()
	if err != nil {
		body := []byte("cannot parse params")
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Add("content-type", "text/plain")
		w.Header().Add("content-length", strconv.Itoa(len(body)))
		w.Write(body)
		return
	}

	rawRedirectURI, ok := getRequiredParam(w, r, "redirect_uri")
	if !ok {
		return
	}

	clientID, ok := getRequiredParam(w, r, "client_id")
	if !ok {
		return
	}

	redirectURI, err := url.Parse(rawRedirectURI)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		body := []byte("malformed redirect_uri")
		w.Header().Set("content-type", "text/plain")
		w.Header().Set("content-length", strconv.Itoa(len(body)))
		w.Write(body)
		return
	}

	client, err := h.clientRepository.GetByID(r.Context(), clientID)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		body := []byte("unauthorized")
		w.Header().Set("content-type", "text/plain")
		w.Header().Set("content-length", strconv.Itoa(len(body)))
		w.Write(body)
		return
	}

	formattedRedirectURIString := fmt.Sprintf("%s://%s%s", redirectURI.Scheme, redirectURI.Host, redirectURI.EscapedPath())
	if client.RawRedirectURI != formattedRedirectURIString {
		q := redirectURI.Query()
		q.Set("error", "unouthorized_client")
		q.Set("error_description", "invalid redirect_uri to client")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	grantType, ok := getRequiredParam(w, r, "grant_type")
	if !ok {
		return
	}

	code, ok := getRequiredParam(w, r, "code")
	if !ok {
		return
	}

	if grantType != "authorization_code" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	authorizationCode, err := h.authorizationCodeEncoder.Decode(code)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user, err := h.userRepository.GetByID(r.Context(), authorizationCode.UserID)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	now := time.Now()
	// TODO: generate AccessToken, TokenType, ExpiresIn, RefreshToken
	accessToken, err := h.internalJWT.EncodeCompact(luaujwt.RegisteredClaims{
		Sub: user.Username,
		// TODO: get from config
		Exp: now.Add(time.Duration(h.expiration) * time.Second).Unix(),
	})
	if err != nil {
		log.Println("AccessToken error")
		w.WriteHeader(500)
		return
	}

	refreshToken, err := h.internalJWT.EncodeCompact(luaujwt.RegisteredClaims{
		Sub: user.Username,
		// TODO: get from config
		Exp: now.Add(time.Duration(5 * time.Hour)).Unix(),
	})
	if err != nil {
		log.Println("RefreshToken error")
		w.WriteHeader(500)
		return
	}

	idToken, err := h.idTokenJWTEncoder.Encode(IDToken{
		Issuer:    "https://luau.com",
		Subject:   user.ID,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Duration(h.expiration) * time.Second),
		Audience:  []string{client.ID},
		// TODO: AtHash
	})

	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := TokenHandlerResponse{
		TokenType:    "Bearer",
		ExpiresIn:    h.expiration,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
	}
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Add("content-type", "application/json")
	w.Write(jsonResponse)
}
