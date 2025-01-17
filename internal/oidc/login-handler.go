package oidc

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/G5Olivieri/luau/internal/clients"
	"github.com/G5Olivieri/luau/internal/csrf"
	"github.com/G5Olivieri/luau/internal/session"
	"github.com/G5Olivieri/luau/internal/users"
	"github.com/julienschmidt/httprouter"
)

type LoginHandler struct {
	clientRepository clients.ClientsRepository
	userRepository   users.UsersRepository
	csrfSync         *csrf.SynchronizerTokenPattern
	httpSession      session.HTTPSession
	codeRepository   CodeRepository
}

func NewLoginHandler(
	clientRepository clients.ClientsRepository,
	userRepository users.UsersRepository,
	csrfSync *csrf.SynchronizerTokenPattern,
	httpSession session.HTTPSession,
	codeRepository CodeRepository,
) LoginHandler {
	return LoginHandler{
		clientRepository: clientRepository,
		userRepository:   userRepository,
		csrfSync:         csrfSync,
		httpSession:      httpSession,
		codeRepository:   codeRepository,
	}
}
func (h LoginHandler) Handle(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	err := r.ParseForm()
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sessionValue, err := h.httpSession.GetFromCookie(r.Context(), r)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	csrfToken := r.FormValue("csrf")
	valid, err := h.csrfSync.Validate(csrfToken, sessionValue)

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

	clientModel, err := h.clientRepository.GetByID(r.Context(), clientID)
	if err != nil {
		q.Set("error", "unouthorized_client")
		q.Set("error_description", err.Error())
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	if clientModel.RawRedirectURI != rawRedirectURI {
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

	userModel, err := h.userRepository.GetByUsernamePassword(r.Context(), username, password)

	if err != nil {
		log.Println("User not found")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	sessionValue.Data["userId"] = userModel.ID
	userModel.LastLogin = time.Now().Unix()

	if _, err = h.userRepository.Update(r.Context(), userModel); err != nil {
		log.Println(err.Error())
		q.Set("error", "server_error")
		q.Set("error_description", "internal server error")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	var nonce, codeChallenge, codeChallengeMethod *string

	sessionNonce, ok := sessionValue.Data[fmt.Sprintf("%s.nonce", clientModel.ID)]
	if ok {
		v, ok := sessionNonce.(string)
		if !ok {
			log.Println("invalid session type to value nonce")
		} else {
			nonce = &v
		}
	}

	sessionCodeChallenge, ok := sessionValue.Data[fmt.Sprintf("%s.code_challenge", clientModel.ID)]
	if ok {
		v, ok := sessionCodeChallenge.(string)
		if !ok {
			log.Println("invalid session type to value code_challenge")
		} else {
			codeChallenge = &v
		}
	}

	sessionCodeChallengeMethod, ok := sessionValue.Data[fmt.Sprintf("%s.code_challenge_method", clientModel.ID)]
	if ok {
		v, ok := sessionCodeChallengeMethod.(string)
		if !ok {
			log.Println("invalid session type to value code_challenge_method")
		} else {
			codeChallengeMethod = &v
		}
	}

	code, err := h.codeRepository.Create(r.Context(), &CodeToCreate{
		User:                userModel,
		Client:              clientModel,
		RedirectURI:         rawRedirectURI,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		// https://www.iana.org/assignments/authentication-method-reference-values/authentication-method-reference-values.xhtml
		AuthenticationMethods: &[]string{"pwd"},
	})

	if err != nil {
		log.Println("Generate Code error")
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	delete(sessionValue.Data, fmt.Sprintf("%s.nonce", clientModel.ID))
	delete(sessionValue.Data, fmt.Sprintf("%s.code_challenge", clientModel.ID))
	delete(sessionValue.Data, fmt.Sprintf("%s.code_challenge_method", clientModel.ID))

	if err = h.httpSession.Save(r.Context(), sessionValue); err != nil {
		log.Println(err.Error())
		q.Set("error", "server_error")
		q.Set("error_description", "internal server error")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return
	}

	q.Set("code", code.ID)
	redirectURI.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}
