package oidc

import (
	"errors"
	"fmt"
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
	"github.com/G5Olivieri/luau/internal/user"
	"github.com/julienschmidt/httprouter"
)

type AuthRequest struct {
	ClientID            string
	RedirectURI         string
	State               string
	ResponseType        string
	Scope               string
	MaxAge              *int
	LoginHint           string
	Nonce               string
	Display             string
	CodeChallenge       string
	CodeChallengeMethod string
	UILocales           string
	Prompt              string
	IDTokenHint         string
	ACRValues           string
	ResponseMode        string
}

type AuthorizePage struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	State        string
	Scope        string
	CSRFToken    string
	LoginHint    string
}

type AuthHandler struct {
	clientRepository client.ClientRepository
	httpSession      session.HTTPSession
	csrfSync         *csrf.SynchronizerTokenPattern
	userRepository   user.UserRepository
	codeRepository   CodeRepository
	tmpl             template.Template
}

func NewAuthHandler(
	clientRepository client.ClientRepository,
	httpSession session.HTTPSession,
	userRepository user.UserRepository,
	csrfSync *csrf.SynchronizerTokenPattern,
	codeRepository CodeRepository,
	tmpl template.Template,
) AuthHandler {
	return AuthHandler{
		clientRepository: clientRepository,
		csrfSync:         csrfSync,
		httpSession:      httpSession,
		userRepository:   userRepository,
		codeRepository:   codeRepository,
		tmpl:             tmpl,
	}
}

func (h AuthHandler) Handle(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	data, ok := h.parseAndValidateAuthRequest(w, r)

	if !ok {
		return
	}

	clientModel, err := h.clientRepository.GetByID(r.Context(), data.ClientID)
	if errors.Is(err, client.ErrNotFound) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if err != nil {
		log.Println(err.Error())
		// TODO: returns errors depending on environment
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if clientModel.RawRedirectURI != data.RedirectURI {
		log.Println("provided redirect uri is not registered redirect uri")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	sessionValue, err := h.httpSession.GetFromCookieOrCreate(r.Context(), w, r)

	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO: prompt == none
	// TODO: prompt == consent
	// TODO: prompt == select_account
	if data.Prompt == "login" {
		h.renderAuthPage(w, r, sessionValue, data)
		return
	}

	sessionUserID, ok := sessionValue.Data["userId"]

	if !ok {
		if data.Nonce != "" {
			// Add nonce in id_token
			sessionValue.Data[fmt.Sprintf("%s.nonce", clientModel.ID)] = data.Nonce
		}

		if data.CodeChallenge != "" {
			sessionValue.Data[fmt.Sprintf("%s.code_challenge", clientModel.ID)] = data.CodeChallenge
			sessionValue.Data[fmt.Sprintf("%s.code_challenge_method", clientModel.ID)] = data.CodeChallengeMethod
		}

		h.renderAuthPage(w, r, sessionValue, data)
		return
	}

	userID, ok := sessionUserID.(string)
	if !ok {
		log.Println("invalid type to userID in session")
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

	state := data.State

	if state != "" {
		q.Set("state", state)
	}

	userModel, err := h.userRepository.GetByID(r.Context(), userID)
	if errors.Is(err, user.ErrNotFound) {
		log.Println("UserID in session not found")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if err != nil {
		log.Println(err.Error())
		redirectError(w, r, *redirectURI, q, "server_error", "internal server error")
		return
	}

	if data.MaxAge != nil {
		if time.Now().Unix() > userModel.LastLogin+int64(*data.MaxAge) {
			h.renderAuthPage(w, r, sessionValue, data)
			return
		}
	}

	// TODO: consent and select_account
	var nonce, codeChallenge, codeChallengeMethod *string
	if data.Nonce != "" {
		nonce = &data.Nonce
	}
	if data.CodeChallenge != "" {
		codeChallenge = &data.CodeChallenge
		codeChallengeMethod = &data.CodeChallengeMethod
	}

	code, err := h.codeRepository.Create(r.Context(), &CodeToCreate{
		User:                userModel,
		Client:              clientModel,
		RedirectURI:         data.RedirectURI,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	})

	if err != nil {
		log.Println("Generate Code error")
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	q.Set("code", code.ID)
	redirectURI.RawQuery = q.Encode()

	ok = h.saveSession(w, r, sessionValue, data)

	if !ok {
		return
	}

	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func (h AuthHandler) renderAuthPage(w http.ResponseWriter, r *http.Request, sessionValue *session.Session, data AuthRequest) {
	csrfToken, err := h.csrfSync.Generate(sessionValue)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	ok := h.saveSession(w, r, sessionValue, data)

	if !ok {
		return
	}

	w.Header().Add("content-type", "text/html")

	// TODO: locales: ui_locales -> cookie -> accept-language
	// TODO: display: popup, touch, wap. I don't know the differences
	h.tmpl.Execute(w, AuthorizePage{
		ClientID:     data.ClientID,
		RedirectURI:  data.RedirectURI,
		ResponseType: data.ResponseType,
		State:        data.State,
		Scope:        data.Scope,
		CSRFToken:    csrfToken,
		LoginHint:    data.LoginHint,
	})
}

func (h AuthHandler) saveSession(w http.ResponseWriter, r *http.Request, sessionValue *session.Session, data AuthRequest) bool {
	if err := h.httpSession.SaveAndSetToCookie(r.Context(), w, sessionValue); err != nil {
		redirectURI, err := url.Parse(data.RedirectURI)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			body := []byte("malformed redirect_uri")
			w.Header().Set("content-type", "text/plain")
			w.Header().Set("content-length", strconv.Itoa(len(body)))
			w.Write(body)
			return false
		}

		q := redirectURI.Query()
		state := data.State
		if state != "" {
			q.Set("state", state)
		}

		q.Set("error", "internal_server_error")
		q.Set("error_description", "cannot save session")
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		return false
	}

	return true
}

func (h AuthHandler) parseAndValidateAuthRequest(w http.ResponseWriter, r *http.Request) (AuthRequest, bool) {
	// TODO: if `request` was provided request params supersedes those passed
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

	maxAgeParamValue, ok := getParamWithRedirect(w, r, "max_age", *redirectURI, q)
	if !ok {
		return AuthRequest{}, false
	}

	var maxAge *int = nil

	if maxAgeParamValue != "" {
		maxAgeIntValue, err := strconv.Atoi(maxAgeParamValue)
		if err != nil {
			log.Println(err.Error())
			redirectError(w, r, *redirectURI, q, "invalid_request", "invalid max_age value")
			return AuthRequest{}, false
		}
		maxAge = &maxAgeIntValue
	}

	loginHint, ok := getParamWithRedirect(w, r, "login_hint", *redirectURI, q)

	if !ok {
		return AuthRequest{}, false
	}

	nonce, ok := getParamWithRedirect(w, r, "nonce", *redirectURI, q)

	if !ok {
		return AuthRequest{}, false
	}

	// TODO: response_mode, display, prompt, ui_locales, id_token_hint, acr_values
	display, ok := getParamWithRedirect(w, r, "display", *redirectURI, q)

	if !ok {
		return AuthRequest{}, false
	}

	if display != "" && display == "page" && display != "popup" && display != "touch" && display != "wap" {
		redirectError(w, r, *redirectURI, q, "invalid_request", "invalid display value")
		return AuthRequest{}, false
	}

	codeChallenge, ok := getParamWithRedirect(w, r, "code_challenge", *redirectURI, q)
	if !ok {
		return AuthRequest{}, false
	}

	codeChallengeMethod, ok := getParamWithRedirect(w, r, "code_challenge_method", *redirectURI, q)
	if !ok {
		return AuthRequest{}, false
	}

	if codeChallengeMethod == "" {
		codeChallengeMethod = "plain"
	}

	if codeChallengeMethod != "plain" && codeChallengeMethod != "S256" {
		redirectError(w, r, *redirectURI, q, "invalid_request", "invalid code_challenge_method value")
		return AuthRequest{}, false
	}

	uiLocales, ok := getParamWithRedirect(w, r, "ui_locales", *redirectURI, q)
	if !ok {
		return AuthRequest{}, false
	}

	prompt, ok := getParamWithRedirect(w, r, "prompt", *redirectURI, q)
	if !ok {
		return AuthRequest{}, false
	}

	if prompt != "" && prompt != "none" && prompt != "login" && prompt != "consent" && prompt != "select_account" {
		redirectError(w, r, *redirectURI, q, "invalid_request", "invalid prompt value")
		return AuthRequest{}, false
	}

	idTokenHint, ok := getParamWithRedirect(w, r, "id_token_hint", *redirectURI, q)
	if !ok {
		return AuthRequest{}, false
	}

	// TODO: Study more
	acrValues, ok := getParamWithRedirect(w, r, "acr_value", *redirectURI, q)
	if !ok {
		return AuthRequest{}, false
	}

	responseMode, ok := getParamWithRedirect(w, r, "response_mode", *redirectURI, q)
	if !ok {
		return AuthRequest{}, false
	}

	// TODO: fragment, form post
	if responseMode != "" && responseMode != "query" {
		redirectError(w, r, *redirectURI, q, "invalid_request", "invalid response_mode value")
		return AuthRequest{}, false
	}

	return AuthRequest{
		ClientID:            clientID,
		RedirectURI:         rawRedirectURI,
		State:               state,
		ResponseType:        responseType,
		Scope:               scope,
		MaxAge:              maxAge,
		LoginHint:           loginHint,
		Nonce:               nonce,
		Display:             display,
		Prompt:              prompt,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		UILocales:           uiLocales,
		IDTokenHint:         idTokenHint,
		ACRValues:           acrValues,
		ResponseMode:        responseMode,
	}, true
}
