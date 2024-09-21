package oidc

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

func getParam(form url.Values, name string) (string, error) {
	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
	// Request and response parameters
	// MUST NOT be included more than once.
	values := form[name]
	if len(values) > 1 {
		return "", fmt.Errorf("%s MUST NOT BE included more than once", name)
	}
	if len(values) == 0 {
		return "", nil
	}
	return values[0], nil
}

func getRequiredParam(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	value, err := getParam(r.Form, name)
	if err != nil {
		body := []byte(err.Error())
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

	if err != nil {
		return redirectError(w, r, redirectURI, query, "invalid_request", err.Error())
	}

	if value == "" {
		return redirectError(w, r, redirectURI, query, "invalid_request", fmt.Sprintf("%s is REQUIRED", name))
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

	if err != nil {
		return redirectError(w, r, redirectURI, query, "invalid_request", err.Error())
	}

	return value, true
}

func redirectError(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI url.URL,
	query url.Values,
	error string,
	description string,
) (string, bool) {
	query.Set("error", error)
	query.Set("error_description", description)
	redirectURI.RawQuery = query.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
	return "", false
}
