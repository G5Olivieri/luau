package oidc

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

func getParam(form url.Values, name string) (string, string) {
	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
	// Request and response parameters
	// MUST NOT be included more than once.
	values := form[name]
	if len(values) > 1 {
		return "", fmt.Sprintf("%s MUST NOT be included more than once", name)
	}
	if len(values) == 0 {
		return "", ""
	}
	return values[0], ""
}

func getRequiredParam(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	value, err := getParam(r.Form, name)
	if err != "" {
		body := []byte(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Add("content-type", "text/plain")
		w.Header().Add("content-length", strconv.Itoa(len(body)))
		w.Write(body)
		return "", false
	}

	if value == "" {
		body := []byte(fmt.Sprintf("%s is REQUIRED", name))
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Add("content-type", "text/plain")
		w.Header().Add("content-length", strconv.Itoa(len(body)))
		w.Write(body)
		return "", false
	}

	return value, true
}

func getRequiredParamWithRedirect(
	w http.ResponseWriter,
	r *http.Request, name string,
	redirectURI url.URL,
	query url.Values,
) (string, bool) {
	value, err := getParam(r.Form, name)

	if err != "" {
		redirectError(w, r, redirectURI, query, "invalid_request", err)
		return "", false
	}

	if value == "" {
		redirectError(w, r, redirectURI, query, "invalid_request", fmt.Sprintf("%s is REQUIRED", name))
		return "", false
	}

	return value, true
}

func getParamWithRedirect(
	w http.ResponseWriter,
	r *http.Request, name string,
	redirectURI url.URL,
	query url.Values,
) (string, bool) {
	value, err := getParam(r.Form, name)

	if err != "" {
		redirectError(w, r, redirectURI, query, "invalid_request", err)
		return "", false
	}

	return value, true
}

func redirectError(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI url.URL,
	query url.Values,
	errorCode string,
	description string,
) {
	query.Set("error", errorCode)
	query.Set("error_description", description)
	redirectURI.RawQuery = query.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}
