package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"text/template"

	"github.com/G5Olivieri/luau/internal/client"
	"github.com/G5Olivieri/luau/internal/csrf"
	"github.com/G5Olivieri/luau/internal/oidc"
	"github.com/G5Olivieri/luau/internal/user"
	"github.com/golang-jwt/jwt/v5"
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

func CSPHandler(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.Header().Add("Content-Security-Policy", "default-src 'self'; object-uri 'none'; frame-ancestors 'none'; base-uri 'none'")
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

	jwtSecretKey := make([]byte, 32)
	_, err = rand.Read(jwtSecretKey)
	if err != nil {
		log.Println("Erro generate csrfSecret")
		log.Fatalln(err.Error())
		return
	}

	// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	// The 32-sized ouput can be used as AES-256 key
	hasher := user.NewArgon2PasswordHasher(1, 46*1024, 1, 32)
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
	csrfMaxAge := 3600
	authorizationCodeEncoder := oidc.NewJWTAuthorizationCodeEncoder(jwt.SigningMethodHS256, func(_ *jwt.Token) (interface{}, error) {
		return codeSecretKey, nil
	})
	idTokenPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Println("GenerateKey")
		log.Fatalln(err.Error())
		return
	}
	idTokenJWTEncoder := oidc.NewIDTokenJWTEncoder(jwt.SigningMethodRS256, func(token *jwt.Token) (interface{}, error) {
		if token == nil {
			return idTokenPrivateKey, nil
		}
		return &idTokenPrivateKey.PublicKey, nil
	})

	authHandler := oidc.NewAuthHandler(clientRepository, oidc.AuthHandlerCSRF{
		TokenGenerator: csrfTokenGenerator,
		Cookie: oidc.AuthHandlerCSRFCookie{
			Name:     csrfCookieName,
			MaxAge:   csrfMaxAge,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
	}, *tmpl)
	loginHandler := oidc.NewLoginHandler(clientRepository, userRepository, csrfTokenGenerator, authorizationCodeEncoder, csrfCookieName)
	tokenHandler := oidc.NewTokenHandler(clientRepository, authorizationCodeEncoder, idTokenJWTEncoder, userRepository, 3*3600)

	r := httprouter.New()
	// Authentication Request MUST support the use of the HTTP GET and POST
	r.GET("/oidc/auth", CSPHandler(authHandler.Handle))
	r.POST("/oidc/auth", CSPHandler(authHandler.Handle))

	r.POST("/oidc/token", NoCacheHandler(tokenHandler.Handle))
	r.POST("/oidc/login", NoCacheHandler(loginHandler.Handle))
	log.Println("Listining :8080")
	http.ListenAndServe(":8080", r)
}
