package oidc

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/G5Olivieri/luau/internal/client"
	"github.com/G5Olivieri/luau/internal/csrf"
	"github.com/G5Olivieri/luau/internal/user"
	"github.com/julienschmidt/httprouter"
)

type AuthorizationCode struct {
	UserID string `json:"user_id"`
	Exp    int64  `json:"exp"`
}

type LoginHandler struct {
	clientRepository          client.ClientRepository
	userRepository            user.UserRepository
	csrfGenerator             csrf.Generator
	authorizationCodeEncoding AuthorizationCodeEncoding
	csrfCookieName            string
}

func NewLoginHandler(clientRepository client.ClientRepository, userRepository user.UserRepository, csrfGenerator csrf.Generator, authorizationCodeEncoding AuthorizationCodeEncoding, csrfCookieName string) LoginHandler {
	return LoginHandler{
		clientRepository:          clientRepository,
		userRepository:            userRepository,
		csrfGenerator:             csrfGenerator,
		authorizationCodeEncoding: authorizationCodeEncoding,
		csrfCookieName:            csrfCookieName,
	}
}
func (h LoginHandler) Handle(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !r.PostForm.Has("redirect_uri") {
		w.WriteHeader(http.StatusBadRequest)
		body := []byte("redirect_uri is REQUIRED")
		w.Header().Set("content-type", "text/plain")
		w.Header().Set("content-length", strconv.Itoa(len(body)))
		w.Write(body)
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

	q := redirectURI.Query()
	state := r.PostForm.Get("state")
	if r.PostForm.Has("state") {
		q.Set("state", state)
	}

	scope := r.PostForm.Get("scope")
	if !strings.Contains(scope, "openid") {
		q.Set("error", "invalid_scope")
		q.Set("error_description", "scope must be contain openid")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	if !r.PostForm.Has("response_type") {
		q.Set("error", "invalid_request")
		q.Set("error_description", "response_type is REQUIRED")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	responseType := r.PostForm.Get("response_type")
	if responseType != "code" {
		q.Set("error", "unsupported_response_type")
		q.Set("error_description", "supported response_type is code")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	if !r.PostForm.Has("client_id") {
		q.Set("error", "invalid_request")
		q.Set("error_description", "client_id is REQUIRED")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	clientID := r.PostForm.Get("client_id")
	client, err := h.clientRepository.GetByID(r.Context(), clientID)
	if err != nil {
		q.Set("error", "unouthorized_client")
		q.Set("error_description", err.Error())
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	formattedRedirectURIString := fmt.Sprintf("%s://%s%s", redirectURI.Scheme, redirectURI.Host, redirectURI.EscapedPath())
	if client.RawRedirectURI != formattedRedirectURIString {
		q.Set("error", "unouthorized_client")
		q.Set("error_description", "invalid redirect_uri to client")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	csrfTokenCookie, err := r.Cookie(h.csrfCookieName)
	if err != nil {
		log.Println(err.Error())
		q.Set("error", "server_error")
		q.Set("error_description", "internal server error")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	valid, err := h.csrfGenerator.Validate(csrfTokenCookie.Value)
	if err != nil {
		log.Println("CSRF Token Validate failure")
		log.Println(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !valid {
		log.Println("Invalid CSRF Token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	username := r.PostForm.Get("username")
	if username == "" {
		log.Println("username is required")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	password := r.PostForm.Get("password")
	if password == "" {
		log.Println("password is required")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user, err := h.userRepository.GetByUsername(r.Context(), username)

	if err != nil {
		log.Println("User not found")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !user.CheckPassword([]byte(password)) {
		log.Println("Invalid password")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	code, err := h.authorizationCodeEncoding.Encode(AuthorizationCode{
		UserID: user.ID,
		Exp:    time.Now().Add(time.Duration(5) * time.Minute).Unix(),
	})

	if err != nil {
		log.Println("Generate Code error")
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	q.Set("code", code)
	redirectURI.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}
