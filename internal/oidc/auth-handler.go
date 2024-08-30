package oidc

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/G5Olivieri/luau/internal/client"
	"github.com/G5Olivieri/luau/internal/csrf"
	"github.com/julienschmidt/httprouter"
)

type AuthorizePage struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	State        string
	Scope        string
}

type AuthHandlerCSRFCookie struct {
	Name      string
	Secure    bool
	HttpOnly  bool
	ExpiresIn time.Duration
}

type AuthHandlerCSRF struct {
	TokenGenerator csrf.Generator
	Cookie         AuthHandlerCSRFCookie
}

type AuthHandler struct {
	clientRepository client.ClientRepository
	csrf             AuthHandlerCSRF
	tmpl             template.Template
}

func NewAuthHandler(
	clientRepository client.ClientRepository,
	csrfTokenGenerator csrf.Generator,
	csrfCookieName string,
	csrfExpiresIn time.Duration,
	tmpl template.Template,
) AuthHandler {
	return AuthHandler{
		clientRepository:   clientRepository,
		csrfTokenGenerator: csrfTokenGenerator,
		csrfCookieName:     csrfCookieName,
		csrfExpiresIn:      csrfExpiresIn,
		tmpl:               tmpl,
	}
}

func (h AuthHandler) Handle(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	rawRedirectURI := r.URL.Query().Get("redirect_uri")
	clientID := r.URL.Query().Get("client_id")

	if clientID == "" {
		body := []byte("client_id is REQUIRED")
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Add("content-type", "text/plain")
		w.Header().Add("content-lenght", strconv.Itoa(len(body)))
		w.Write(body)
		return
	}

	if rawRedirectURI == "" {
		w.WriteHeader(http.StatusBadRequest)
		body := []byte("redirect_uri is REQUIRED")
		w.Header().Set("content-type", "text/plain")
		w.Header().Set("content-length", strconv.Itoa(len(body)))
		w.Write(body)
		return
	}

	redirectURI, err := url.Parse(r.URL.Query().Get("redirect_uri"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		body := []byte("malformed redirect_uri")
		w.Header().Set("content-type", "text/plain")
		w.Header().Set("content-length", strconv.Itoa(len(body)))
		w.Write(body)
		return
	}

	c, err := h.clientRepository.GetByID(r.Context(), clientID)
	if errors.Is(err, client.NotFoundErr) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if err != nil {
		log.Println(err.Error())
		// TODO: returns errors depending on environment
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if c.RawRedirectURI != rawRedirectURI {
		log.Println("provided redirect uri is not registered redirect uri")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	q := redirectURI.Query()
	state := r.URL.Query().Get("state")
	if state != "" {
		q.Set("state", state)
	}

	responseType := r.URL.Query().Get("response_type")
	if responseType == "" {
		q.Set("error", "invalid_request")
		q.Set("error_description", "response_type is REQUIRED")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	if responseType != "code" {
		log.Printf("unsupported response_type '%s'\n", responseType)
		q.Set("error", "unsupported_response_type")
		q.Set("error_description", "supported response_type is code")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	scope := r.URL.Query().Get("scope")
	if !strings.Contains(scope, "openid") {
		log.Printf("invalid_scope '%s'\n", scope)
		q.Set("error", "invalid_scope")
		q.Set("error_description", "scope must be contain openid")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	csrf, err := h.csrf.TokenGenerator.Generate()
	if err != nil {
		log.Println(err.Error())
		q.Set("error", "server_error")
		q.Set("error_description", "internal server error")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	csrfCookie := http.Cookie{
		Name:     h.csrf.Cookie.Name,
		Value:    csrf,
		Expires:  time.Now().Add(h.csrf.Cookie.ExpiresIn),
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, &csrfCookie)

	w.Header().Add("content-type", "text/html")
	h.tmpl.Execute(w, AuthorizePage{
		ClientID:     clientID,
		RedirectURI:  redirectURI.String(),
		ResponseType: responseType,
		State:        state,
		Scope:        scope,
	})
}
