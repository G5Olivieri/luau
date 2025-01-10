package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/G5Olivieri/luau/internal/client"
	"github.com/G5Olivieri/luau/internal/csrf"
	"github.com/G5Olivieri/luau/internal/jwk"
	"github.com/G5Olivieri/luau/internal/kms"
	"github.com/G5Olivieri/luau/internal/oidc"
	"github.com/G5Olivieri/luau/internal/session"
	"github.com/G5Olivieri/luau/internal/user"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func CORSHandler(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	origin := r.Header.Get("origin")
	if origin != "" {
		w.Header().Add("Access-Control-Allow-Origin", origin)
		w.Header().Add("Access-Control-Allow-Methods", "POST")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Add("Access-Control-Max-Age", "86400")
	}
}

func CORSHandlerMiddleware(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		CORSHandler(w, r, p)
		h(w, r, p)
	}
}

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
		log.Println("Error generate codeSecretKey")
		log.Fatalln(err.Error())
		return
	}

	csrfSecret := make([]byte, 32)
	_, err = rand.Read(csrfSecret)
	if err != nil {
		log.Println("Error generate csrfSecret")
		log.Fatalln(err.Error())
		return
	}

	jwtSecretKey := make([]byte, 32)
	_, err = rand.Read(jwtSecretKey)
	if err != nil {
		log.Println("Error generate csrfSecret")
		log.Fatalln(err.Error())
		return
	}

	// https://en.wikipedia.org/wiki/Argon2
	salt := make([]byte, 16)
	_, err = rand.Read(salt)
	if err != nil {
		log.Println("generate password salt error")
		log.Fatalln(err.Error())
		return
	}

	// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	// The 32-sized ouput can be used as AES-256 key
	hasher := user.NewArgon2PasswordHasher(1, 46*1024, 1, 32)
	password, err := user.NewHashSaltPassword([]byte("glayson"), salt, hasher)
	if err != nil {
		log.Println("new password error")
		log.Fatalln(err.Error())
		return
	}

	userID := uuid.NewString()
	users := make(map[string]*user.User)
	users[userID] = &user.User{
		ID:        userID,
		Username:  "glayson",
		Password:  password,
		LastLogin: 0,
	}
	userRepository := user.NewInMemoryUserRepository(users)

	addr := "localhost:50051"
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()

	clientRepository := client.NewGRPCClientRepository(conn)

	sessionStore := session.NewInMemorySessionStore(make(map[string]*session.Session))
	httpSession := session.NewHttpSession(sessionStore, "session", 14*time.Hour)

	csrfSync := csrf.NewSynchronizerTokenPattern(httpSession, "csrf")

	codeRepository := oidc.NewInMemoryCodeRepository(make(map[string]*oidc.Code), 5*time.Minute)

	kmsvalue := kms.NewInMemoryKMS()

	timeoutContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	accessTokenKey, err := kmsvalue.GenerateKey(timeoutContext, kms.KeySpec{
		Alg:    jwk.KeyAlgRS256,
		Type:   jwk.KeyTypeRSA,
		Use:    jwk.KeyUseSig,
		KeyOps: []jwk.KeyOps{jwk.KeyOpsSign, jwk.KeyOpsVerify},
	})

	if err != nil {
		log.Fatal(err)
	}

	timeoutContext, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	refreshTokenKey, err := kmsvalue.GenerateKey(timeoutContext, kms.KeySpec{
		Alg:    jwk.KeyAlgHS256,
		Type:   jwk.KeyTypeOct,
		Use:    jwk.KeyUseSig,
		KeyOps: []jwk.KeyOps{jwk.KeyOpsSign, jwk.KeyOpsVerify},
	})

	if err != nil {
		log.Fatal(err)
	}

	timeoutContext, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	idTokenKey, err := kmsvalue.GenerateKey(timeoutContext, kms.KeySpec{
		Alg:    jwk.KeyAlgES256,
		Type:   jwk.KeyTypeEC,
		Use:    jwk.KeyUseSig,
		KeyOps: []jwk.KeyOps{jwk.KeyOpsSign, jwk.KeyOpsVerify},
	})

	if err != nil {
		log.Fatal(err)
	}

	issuer := "https://luau.org"
	idTokenJWTEncoder := oidc.NewIDTokenJWTEncoder(kmsvalue, issuer, 2*60*60, idTokenKey.GetID())                // 2 hours
	accessTokenEncoder := oidc.NewAccessTokenJWTEncoder(kmsvalue, issuer, 50*60, accessTokenKey.GetID())         // 50 minutes
	refreshTokenEncoder := oidc.NewRefreshTokenJWTEncoder(kmsvalue, issuer, 2*24*60*50, refreshTokenKey.GetID()) // 2 days

	authHandler := oidc.NewAuthHandler(clientRepository, httpSession, userRepository, csrfSync, codeRepository, *tmpl)
	loginHandler := oidc.NewLoginHandler(clientRepository, userRepository, csrfSync, httpSession, codeRepository)
	tokenHandler := oidc.NewTokenHandler(
		clientRepository,
		userRepository,
		codeRepository,
		httpSession,
		accessTokenEncoder,
		refreshTokenEncoder,
		idTokenJWTEncoder,
	)

	r := httprouter.New()
	// Authentication Request MUST support the use of the HTTP GET and POST
	r.GET("/oidc/auth", CSPHandler(authHandler.Handle))
	r.POST("/oidc/auth", CSPHandler(authHandler.Handle))

	r.POST("/oidc/token", CORSHandlerMiddleware(NoCacheHandler(tokenHandler.Handle)))
	r.POST("/oidc/login", NoCacheHandler(loginHandler.Handle))

	r.GET("/oidc/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		jwks, err := kmsvalue.JWKSPublicKeys()
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		jwksResponse := make(map[string]interface{})
		jwksResponse["jwks"] = jwks
		json.NewEncoder(w).Encode(jwksResponse)
	})

	log.Println("Listening :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
