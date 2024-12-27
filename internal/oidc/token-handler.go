package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/G5Olivieri/luau/internal/client"
	"github.com/G5Olivieri/luau/internal/session"
	"github.com/G5Olivieri/luau/internal/user"
	"github.com/julienschmidt/httprouter"
)

type TokenHandlerResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

type TokenHandler struct {
	clientRepository    client.ClientRepository
	codeRepository      CodeRepository
	userRepository      user.UserRepository
	idTokenJWTEncoder   IDTokenJWTEncoder
	accessTokenEncoder  AccessTokenEncoder
	refreshTokenEncoder RefreshTokenEncoder
	httpSession         session.HTTPSession
}

func NewTokenHandler(
	clientRepository client.ClientRepository,
	userRepository user.UserRepository,
	codeRepository CodeRepository,
	httpSession session.HTTPSession,
	accessTokenEncoder AccessTokenEncoder,
	refreshTokenEncoder RefreshTokenEncoder,
	idTokenJWTEncoder IDTokenJWTEncoder,
) TokenHandler {
	return TokenHandler{
		clientRepository:    clientRepository,
		codeRepository:      codeRepository,
		userRepository:      userRepository,
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

	rawRedirectURI, ok := getRequiredParam(w, r, "redirect_uri")
	if !ok {
		return
	}

	clientID, ok := getRequiredParam(w, r, "client_id")
	if !ok {
		return
	}

	grantType, ok := getRequiredParam(w, r, "grant_type")

	if !ok {
		return
	}

	if grantType != "authorization_code" {
		w.WriteHeader(http.StatusBadRequest)
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
	if err = h.codeRepository.Delete(r.Context(), *code); err != nil {
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

	accessToken, err := h.accessTokenEncoder.Encode(r.Context(), AccessTokenRequest{
		Sub:      userModel.Username,
		Audience: []string{clientID},
	})

	if err != nil {
		log.Println("AccessToken error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	refreshToken, err := h.refreshTokenEncoder.Encode(r.Context(), RefreshTokenRequest{
		Sub:      userModel.Username,
		Audience: []string{clientID},
	})

	if err != nil {
		log.Println("RefreshToken error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	idToken, err := h.idTokenJWTEncoder.Encode(r.Context(), IDTokenRequest{
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
