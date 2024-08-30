package oidc

import (
	"log"
	"net/http"
	"net/url"
	"strconv"

	"github.com/G5Olivieri/luau/internal/client"
	"github.com/G5Olivieri/luau/internal/user"
	"github.com/julienschmidt/httprouter"
)

type TokenHandler struct {
	clientRepository          client.ClientRepository
	authorizationCodeEncoding AuthorizationCodeEncoding
	userRepository            user.UserRepository
}

func NewTokenHandler(
	clientRepository client.ClientRepository,
	authorizationCodeEncoding AuthorizationCodeEncoding,
	userRepository user.UserRepository,
) TokenHandler {
	return TokenHandler{
		clientRepository:          clientRepository,
		authorizationCodeEncoding: authorizationCodeEncoding,
		userRepository:            userRepository,
	}
}

func (h TokenHandler) Handle(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	grantType := r.PostForm.Get("grant_type")
	if grantType == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	rawRedirectURI := r.PostForm.Get("redirect_uri")
	if rawRedirectURI == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	code := r.PostForm.Get("code")
	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	clientID := r.PostForm.Get("client_id")
	if clientID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if grantType != "authorization_code" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	redirectURI, err := url.Parse(r.PostForm.Get("redirect_uri"))
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
		q := redirectURI.Query()
		q.Set("error", "unouthorized_client")
		q.Set("error_description", err.Error())
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	if client.RawRedirectURI != rawRedirectURI {
		q := redirectURI.Query()
		q.Set("error", "unouthorized_client")
		q.Set("error_description", "invalid redirect_uri to client")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	authorizationCode, err := h.authorizationCodeEncoding.Decode(code)
	if err != nil {
		log.Println("decode code error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user, err := h.userRepository.GetByID(r.Context(), authorizationCode.UserID)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// TODO:: generate AccessToken, TokenType, ExpiresIn, RefreshToken, ID Token
	w.Write([]byte(user.ID))
}
