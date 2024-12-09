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
	"github.com/G5Olivieri/luau/internal/session"
	"github.com/google/uuid"
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

type AuthHandler struct {
	clientRepository         client.ClientRepository
	csrfTokenGenerator       csrf.Generator
	sessionStore             session.SessionStore
	authorizationCodeEncoder AuthorizationCodeEncoder
	tmpl                     template.Template
}

func NewAuthHandler(
	clientRepository client.ClientRepository,
	csrfTokenGenerator csrf.Generator,
	sessionStore session.SessionStore,
	authorizationCodeEncoder AuthorizationCodeEncoder,
	tmpl template.Template,
) AuthHandler {
	return AuthHandler{
		clientRepository:         clientRepository,
		csrfTokenGenerator:       csrfTokenGenerator,
		sessionStore:             sessionStore,
		authorizationCodeEncoder: authorizationCodeEncoder,
		tmpl:                     tmpl,
	}
}

type AuthRequest struct {
	ClientID     string
	RedirectURI  string
	State        string
	ResponseType string
	Scope        string
}

// TODO: response_mode, nonce, display, prompt, max_age, ui_locales, id_token_hint, login_hint, acr_values
func (h AuthHandler) Handle(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	data, ok := h.parseAndValidateAuthRequest(w, r)

	if !ok {
		return
	}

	c, err := h.clientRepository.GetByID(r.Context(), data.ClientID)
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

	if c.RawRedirectURI != data.RedirectURI {
		log.Println("provided redirect uri is not registered redirect uri")
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

	if v, ok := sessionValue.Data["userId"]; ok {
		userID, ok := v.(string)
		if ok {
			code, err := h.authorizationCodeEncoder.Encode(AuthorizationCode{
				UserID: userID,
				// short-lived token, less than 10 minutes
				Exp: time.Now().Add(time.Duration(5) * time.Minute),
			})

			if err != nil {
				log.Println(err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			redirectURI, err := url.Parse(data.RedirectURI)
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

			q.Set("code", code)
			redirectURI.RawQuery = q.Encode()
			http.Redirect(w, r, redirectURI.String(), http.StatusFound)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		HttpOnly: true,
		Secure:   true,
	})

	h.sessionStore.Set(r.Context(), sessionValue)

	csrfToken, cookieCsrfToken, err := h.csrfTokenGenerator.Generate()
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// TODO: create a session
	// TODO: create csrf token using https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern

	w.Header().Add("content-type", "text/html")
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf",
		Value:    cookieCsrfToken,
		HttpOnly: true,
		Secure:   true,
	})
	h.tmpl.Execute(w, AuthorizePage{
		ClientID:     data.ClientID,
		RedirectURI:  data.RedirectURI,
		ResponseType: data.ResponseType,
		State:        data.State,
		Scope:        data.Scope,
		CSRFToken:    csrfToken,
	})
}

func (h AuthHandler) parseAndValidateAuthRequest(w http.ResponseWriter, r *http.Request) (AuthRequest, bool) {
	if r.Method == http.MethodPost {
		if r.Header.Get("content-type") != "application/x-www-form-urlencoded" {
			body := []byte("Content-Type is invalid")
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Add("content-type", "text/plain")
			w.Header().Add("content-length", strconv.Itoa(len(body)))
			w.Write(body)
			return AuthRequest{}, false
		}
	}
	err := r.ParseForm()
	if err != nil {
		body := []byte("cannot parse params")
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Add("content-type", "text/plain")
		w.Header().Add("content-length", strconv.Itoa(len(body)))
		w.Write(body)
		return AuthRequest{}, false
	}

	clientID, ok := getRequiredParam(w, r, "client_id")

	if !ok {
		return AuthRequest{}, false
	}

	rawRedirectURI, ok := getRequiredParam(w, r, "redirect_uri")

	if !ok {
		return AuthRequest{}, false
	}

	redirectURI, err := url.Parse(rawRedirectURI)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		body := []byte("malformed redirect_uri")
		w.Header().Set("content-type", "text/plain")
		w.Header().Set("content-length", strconv.Itoa(len(body)))
		w.Write(body)
		return AuthRequest{}, false
	}

	q := redirectURI.Query()
	state, ok := getParamWithRedirect(w, r, "state", *redirectURI, q)

	if !ok {
		return AuthRequest{}, false
	}

	if state != "" {
		q.Set("state", state)
	}

	responseType, ok := getRequiredParamWithRedirect(w, r, "response_type", *redirectURI, q)

	if !ok {
		return AuthRequest{}, false
	}

	if responseType != "code" {
		log.Printf("unsupported response_type '%s'\n", responseType)
		q.Set("error", "unsupported_response_type")
		q.Set("error_description", "supported response_type is code")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return AuthRequest{}, false
	}

	scope, ok := getRequiredParamWithRedirect(w, r, "scope", *redirectURI, q)

	if !ok {
		return AuthRequest{}, false
	}

	if !strings.Contains(scope, "openid") {
		log.Printf("invalid_scope '%s'\n", scope)
		q.Set("error", "invalid_scope")
		q.Set("error_description", "scope MUST contain openid")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return AuthRequest{}, false
	}

	return AuthRequest{
		ClientID:     clientID,
		RedirectURI:  rawRedirectURI,
		State:        state,
		ResponseType: responseType,
		Scope:        scope,
	}, true
}
