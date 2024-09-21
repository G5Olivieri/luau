package oidc

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"

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
	CSRFToken    string
}

type AuthHandlerCSRFCookie struct {
	Name     string
	Secure   bool
	HttpOnly bool
	MaxAge   int
	SameSite http.SameSite
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
	csrfConfig AuthHandlerCSRF,
	tmpl template.Template,
) AuthHandler {
	return AuthHandler{
		clientRepository: clientRepository,
		csrf: AuthHandlerCSRF{
			TokenGenerator: csrfConfig.TokenGenerator,
			Cookie: AuthHandlerCSRFCookie{
				Name:     csrfConfig.Cookie.Name,
				MaxAge:   csrfConfig.Cookie.MaxAge,
				Secure:   csrfConfig.Cookie.Secure,
				HttpOnly: csrfConfig.Cookie.HttpOnly,
				SameSite: csrfConfig.Cookie.SameSite,
			},
		},
		tmpl: tmpl,
	}
}

// TODO: response_mode, nonce, display, prompt, max_age, ui_locales, id_token_hint, login_hint, acr_values
func (h AuthHandler) Handle(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if r.Method == http.MethodPost {
		if r.Header.Get("content-type") != "application/x-www-form-urlencoded" {
			body := []byte("Content-Type is invalid")
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Add("content-type", "text/plain")
			w.Header().Add("content-length", strconv.Itoa(len(body)))
			w.Write(body)
			return
		}
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

	clientID, ok := getRequiredParam(w, r, "client_id")

	if !ok {
		return
	}

	rawRedirectURI, ok := getRequiredParam(w, r, "redirect_uri")

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
	state, ok := getParamWithRedirect(w, r, "state", *redirectURI, q)

	if !ok {
		return
	}

	if state != "" {
		q.Set("state", state)
	}

	responseType, ok := getRequiredParamWithRedirect(w, r, "response_type", *redirectURI, q)

	if !ok {
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

	scope, ok := getRequiredParamWithRedirect(w, r, "scope", *redirectURI, q)

	if !ok {
		return
	}

	if !strings.Contains(scope, "openid") {
		log.Printf("invalid_scope '%s'\n", scope)
		q.Set("error", "invalid_scope")
		q.Set("error_description", "scope MUST contain openid")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	csrfToken, err := h.csrf.TokenGenerator.Generate()
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
		Value:    csrfToken,
		MaxAge:   h.csrf.Cookie.MaxAge,
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, &csrfCookie)

	w.Header().Add("content-type", "text/html")

	// TODO: create a session

	h.tmpl.Execute(w, AuthorizePage{
		ClientID:     clientID,
		RedirectURI:  redirectURI.String(),
		ResponseType: responseType,
		State:        state,
		Scope:        scope,
		CSRFToken:    csrfToken,
	})
}
