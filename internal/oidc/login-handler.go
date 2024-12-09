package oidc

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/G5Olivieri/luau/internal/client"
	"github.com/G5Olivieri/luau/internal/csrf"
	"github.com/G5Olivieri/luau/internal/session"
	"github.com/G5Olivieri/luau/internal/user"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
)

type AuthorizationCode struct {
	UserID string
	Exp    time.Time
}

type LoginHandler struct {
	clientRepository         client.ClientRepository
	userRepository           user.UserRepository
	authorizationCodeEncoder AuthorizationCodeEncoder
	csrfTokenGenerator       csrf.Generator
	sessionStore             session.SessionStore
}

func NewLoginHandler(
	clientRepository client.ClientRepository,
	userRepository user.UserRepository,
	authorizationCodeEncoder AuthorizationCodeEncoder,
	csrfTokenGenerator csrf.Generator,
	sessionStore session.SessionStore,
) LoginHandler {
	return LoginHandler{
		clientRepository:         clientRepository,
		userRepository:           userRepository,
		authorizationCodeEncoder: authorizationCodeEncoder,
		csrfTokenGenerator:       csrfTokenGenerator,
		sessionStore:             sessionStore,
	}
}
func (h LoginHandler) Handle(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	err := r.ParseForm()
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	csrfToken := r.FormValue("csrf")
	cookieCsrfToken, err := r.Cookie("csrf")

	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Invalid CSRF token", http.StatusBadRequest)
		return
	}

	log.Printf("csrfToken %s, cookie %s\n", csrfToken, cookieCsrfToken.Value)

	valid, err := h.csrfTokenGenerator.Validate(csrfToken, cookieCsrfToken.Value)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Invalid CSRF token", http.StatusBadRequest)
		return
	}

	if !valid {
		http.Error(w, "Invalid CSRF token", http.StatusBadRequest)
		return
	}

	rawRedirectURI := r.Form.Get("redirect_uri")
	if rawRedirectURI == "" {
		w.WriteHeader(http.StatusBadRequest)
		body := []byte("redirect_uri is REQUIRED")
		w.Header().Set("content-type", "text/plain")
		w.Header().Set("content-length", strconv.Itoa(len(body)))
		w.Write(body)
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

	q := redirectURI.Query()
	state := r.Form.Get("state")
	if state != "" {
		q.Set("state", state)
	}

	scope := r.Form.Get("scope")
	if !strings.Contains(scope, "openid") {
		q.Set("error", "invalid_scope")
		q.Set("error_description", "scope must be contain openid")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	responseType := r.Form.Get("response_type")

	if responseType == "" {
		q.Set("error", "invalid_request")
		q.Set("error_description", "response_type is REQUIRED")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	if responseType != "code" {
		q.Set("error", "unsupported_response_type")
		q.Set("error_description", "supported response_type is code")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	clientID := r.Form.Get("client_id")
	if clientID == "" {
		q.Set("error", "invalid_request")
		q.Set("error_description", "client_id is REQUIRED")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	client, err := h.clientRepository.GetByID(r.Context(), clientID)
	if err != nil {
		q.Set("error", "unouthorized_client")
		q.Set("error_description", err.Error())
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	if client.RawRedirectURI != rawRedirectURI {
		q.Set("error", "unouthorized_client")
		q.Set("error_description", "invalid redirect_uri to client")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
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

	sessionIDCookie, err := r.Cookie("session")
	var sessionID string
	var sessionValue *session.Session

	if errors.Is(err, http.ErrNoCookie) {
		log.Println(err.Error())
		sessionID = uuid.NewString()
	} else if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	} else {
		sessionID = sessionIDCookie.Value
		log.Printf("Cookie found '%s'\n", sessionID)
		if sessionID == "" {
			sessionID = uuid.NewString()
		}
	}

	sessionValue, err = h.sessionStore.Get(r.Context(), sessionID)
	if errors.Is(err, session.ErrNotFound) {
		log.Println(err.Error())
		sessionValue = &session.Session{
			ID:   sessionID,
			Data: make(map[string]interface{}),
		}
	} else if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sessionValue.Data["userId"] = user.ID
	h.sessionStore.Set(r.Context(), sessionValue)

	code, err := h.authorizationCodeEncoder.Encode(AuthorizationCode{
		UserID: user.ID,
		// short-lived token, less than 10 minutes
		Exp: time.Now().Add(time.Duration(5) * time.Minute),
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
