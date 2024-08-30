package main

import (
	"crypto/rand"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/G5Olivieri/luau/internal/client"
	"github.com/G5Olivieri/luau/internal/csrf"
	"github.com/G5Olivieri/luau/internal/oidc"
	"github.com/G5Olivieri/luau/internal/user"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
)

func NoCacheHandler(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.Header().Add("cache-control", "no-cache, no-store, must-revalidate")
		w.Header().Add("pragma", "no-cache")
		w.Header().Add("expires", "0")
		h(w, r, p)
	}
}

func main() {
	tmpl := template.Must(template.ParseFiles("templates/authorize.html"))

	codeSecretKey := make([]byte, 32)
	_, err := rand.Read(codeSecretKey)
	if err != nil {
		log.Println("Erro generate codeSecretKey")
		log.Fatalln(err.Error())
		return
	}

	csrfSecret := make([]byte, 32)
	_, err = rand.Read(csrfSecret)
	if err != nil {
		log.Println("Erro generate csrfSecret")
		log.Fatalln(err.Error())
		return
	}

	// https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#signed-double-submit-cookie-recommended
	hasher := user.NewArgon2PasswordHasher(2, 15*1024, 1, 32)
	password, err := user.NewPassword([]byte("glayson"), hasher)
	if err != nil {
		log.Println("new password error")
		log.Fatalln(err.Error())
		return
	}

	userRepository := user.NewInMemoryUserRepository([]user.User{
		{
			ID:       uuid.NewString(),
			Username: "glayson",
			Password: password,
		},
	})
	clientRepository := client.NewInMemoryClientRepository([]client.Client{
		{ID: "glayssinho", RawRedirectURI: "http://localhost:3000/callback"},
	})

	csrfTokenGenerator := csrf.NewHMACGenerator(csrfSecret)
	csrfCookieName := "csrf_token"
	csrfExpiresIn := time.Duration(5) * time.Minute

	authorizationAuthorizationCodeEncoding := oidc.NewAESAuthorizationCodeEncoding(codeSecretKey)

	authHandler := oidc.NewAuthHandler(clientRepository, oidc.AuthHandlerCSRF{
		TokenGenerator: csrf.NewHMACGenerator(csrfSecret),
		Cookie: oidc.AuthHandlerCSRFCookie{
			Name:      csrfCookieName,
			ExpiresIn: csrfExpiresIn,
			Secure:    true,
			HttpOnly:  true,
		},
	}, *tmpl)
	loginHandler := oidc.NewLoginHandler(clientRepository, userRepository, csrfTokenGenerator, authorizationAuthorizationCodeEncoding, csrfCookieName)
	tokenHandler := oidc.NewTokenHandler(clientRepository, authorizationAuthorizationCodeEncoding, userRepository)

	r := httprouter.New()
	r.GET("/oidc/auth", authHandler.Handle)
	r.POST("/oidc/token", NoCacheHandler(tokenHandler.Handle))
	r.POST("/oidc/login", NoCacheHandler(loginHandler.Handle))
	log.Println("Listining :8080")
	http.ListenAndServe(":8080", r)
}
