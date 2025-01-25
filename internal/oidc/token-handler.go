package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/G5Olivieri/luau/internal/clients"
	oidcencoding "github.com/G5Olivieri/luau/internal/oidc/encoding"
	"github.com/G5Olivieri/luau/internal/session"
	"github.com/G5Olivieri/luau/internal/users"
	"github.com/julienschmidt/httprouter"
)

type TokenHandlerResponse struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int64   `json:"expires_in"`
	RefreshToken string  `json:"refresh_token"`
	IDToken      *string `json:"id_token,omitempty"`
}

type TokenHandler struct {
	clientRepository    clients.ClientsRepository
	codeRepository      CodeRepository
	userRepository      users.UsersRepository
	idTokenJWTEncoder   oidcencoding.IDTokenJWTEncoder
	accessTokenEncoder  oidcencoding.AccessTokenEncoder
	refreshTokenEncoder oidcencoding.RefreshTokenEncoder
	httpSession         session.HTTPSession
}

func NewTokenHandler(
	clientsRepository clients.ClientsRepository,
	usersRepository users.UsersRepository,
	codeRepository CodeRepository,
	httpSession session.HTTPSession,
	accessTokenEncoder oidcencoding.AccessTokenEncoder,
	refreshTokenEncoder oidcencoding.RefreshTokenEncoder,
	idTokenJWTEncoder oidcencoding.IDTokenJWTEncoder,
) TokenHandler {
	return TokenHandler{
		clientRepository:    clientsRepository,
		codeRepository:      codeRepository,
		userRepository:      usersRepository,
		idTokenJWTEncoder:   idTokenJWTEncoder,
		httpSession:         httpSession,
		accessTokenEncoder:  accessTokenEncoder,
		refreshTokenEncoder: refreshTokenEncoder,
	}
}

func (h TokenHandler) Handle(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	contentType := r.Header.Get("content-type")

	if contentType != "application/x-www-form-urlencoded" {
		log.Println("invalid request content-type")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err := r.ParseForm()
	if err != nil {
		body := []byte("cannot parse params")
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Add("content-type", "text/plain")
		w.Header().Add("content-length", strconv.Itoa(len(body)))
		w.Write(body)
		return
	}

	grantType, ok := getRequiredParam(w, r, "grant_type")

	if !ok {
		return
	}

	if grantType == "authorization_code" {
		h.handleCode(w, r)
		return
	}

	if grantType == "client_credentials" {
		h.handleClientCredential(w, r)
		return
	}

	w.WriteHeader(http.StatusBadRequest)
}

func (h TokenHandler) handleCode(w http.ResponseWriter, r *http.Request) {
	rawRedirectURI, ok := getRequiredParam(w, r, "redirect_uri")
	if !ok {
		return
	}

	clientID, ok := getRequiredParam(w, r, "client_id")
	if !ok {
		return
	}
	codeID, ok := getRequiredParam(w, r, "code")
	if !ok {
		return
	}

	code, err := h.codeRepository.GetByID(r.Context(), codeID)

	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// It doesn't allowed to use code twice
	if err = h.codeRepository.Delete(r.Context(), code); err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO: confidential client type
	if code.Client.ID != clientID {
		log.Println("Client isn't same")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if code.RedirectURI != rawRedirectURI {
		log.Println("RedirectURI isn't same")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if time.Now().Unix() < code.ExpireAt {
		log.Println("Expired code")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if code.CodeChallenge != nil && code.CodeChallengeMethod != nil {
		codeVerifier, err := getParam(r.Form, "code_verifier")
		if err != "" {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if *code.CodeChallengeMethod == "plain" {
			if codeVerifier != *code.CodeChallenge {
				log.Println("invalid code_challenge")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		} else if *code.CodeChallengeMethod == "S256" {
			hashedVerifier := sha256.Sum256([]byte(codeVerifier))
			if base64.RawURLEncoding.EncodeToString(hashedVerifier[:]) != *code.CodeChallenge {
				log.Println("invalid code_challenge")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		} else {
			log.Println("invalid code_challenge_method in repository")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	userModel, err := h.userRepository.GetByID(r.Context(), code.User.ID)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	accessToken, err := h.accessTokenEncoder.Encode(r.Context(), oidcencoding.AccessTokenRequest{
		Sub:      userModel.Username,
		Audience: []string{clientID},
	})

	if err != nil {
		log.Println("AccessToken error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	refreshToken, err := h.refreshTokenEncoder.Encode(r.Context(), oidcencoding.RefreshTokenRequest{
		Sub:      userModel.Username,
		Audience: []string{clientID},
	})

	if err != nil {
		log.Println("RefreshToken error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	idToken, err := h.idTokenJWTEncoder.Encode(r.Context(), oidcencoding.IDTokenRequest{
		Subject:  userModel.ID,
		Audience: []string{code.Client.ID},
		Nonce:    code.Nonce,
		AuthTime: &code.CreatedAt,
		Amr:      code.AuthenticationMethods,
	})

	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := TokenHandlerResponse{
		TokenType:    "Bearer",
		ExpiresIn:    h.accessTokenEncoder.ExpiresIn(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      &idToken,
	}
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Add("content-type", "application/json")
	w.Write(jsonResponse)

}

func (h TokenHandler) handleClientCredential(w http.ResponseWriter, r *http.Request) {
	authorizationHeader := r.Header.Get("authorization")
	if authorizationHeader == "" {
		log.Println("authorization header is empty")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	parts := strings.Split(authorizationHeader, " ")
	if len(parts) != 2 || parts[0] != "Basic" {
		log.Println("authorization header malformed")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	cred, err := base64.StdEncoding.DecodeString(parts[1])

	if err != nil {
		log.Println("authorization header credential is not base64 encoded")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	credParts := strings.Split(string(cred), ":")
	if len(credParts) != 2 {
		log.Println("credential is malformed")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	clientID := credParts[0]
	clientSecret := credParts[1]

	client, err := h.clientRepository.GetByID(r.Context(), clientID)

	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !hmac.Equal([]byte(client.Secret), []byte(clientSecret)) {
		log.Println("secrets is not equal", client.Secret, clientSecret)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	accessToken, err := h.accessTokenEncoder.Encode(r.Context(), oidcencoding.AccessTokenRequest{
		Sub:      client.ID,
		Audience: []string{clientID},
	})

	if err != nil {
		log.Println("AccessToken error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	refreshToken, err := h.refreshTokenEncoder.Encode(r.Context(), oidcencoding.RefreshTokenRequest{
		Sub:      client.ID,
		Audience: []string{clientID},
	})

	if err != nil {
		log.Println("RefreshToken error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := TokenHandlerResponse{
		TokenType:    "Bearer",
		ExpiresIn:    h.accessTokenEncoder.ExpiresIn(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Add("content-type", "application/json")
	w.Write(jsonResponse)

}
