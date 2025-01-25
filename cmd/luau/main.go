package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"text/template"
	"time"

	"github.com/G5Olivieri/luau/internal/clients"
	"github.com/G5Olivieri/luau/internal/config"
	"github.com/G5Olivieri/luau/internal/csrf"
	"github.com/G5Olivieri/luau/internal/kms"
	"github.com/G5Olivieri/luau/internal/oidc"
	oidcencoding "github.com/G5Olivieri/luau/internal/oidc/encoding"
	"github.com/G5Olivieri/luau/internal/session"
	"github.com/G5Olivieri/luau/internal/users"
	"github.com/G5Olivieri/luau/jose/jwk"
	"github.com/julienschmidt/httprouter"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// TODO: CORS Config
func CORSHandler(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	origin := r.Header.Get("origin")
	if origin != "" {
		w.Header().Add("Access-Control-Allow-Origin", origin)
		w.Header().Add("Access-Control-Allow-Methods", "POST")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type,x-requested-with")
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

func newGrpcConn(addr, serverName string, configValue config.Config) (*grpc.ClientConn, error) {
	if configValue.GrpcInsecure {
		return grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		cert, err := tls.LoadX509KeyPair(configValue.ClientCertPath, configValue.ClientCertPrivateKeyPath)
		if err != nil {
			log.Fatalf("failed to load key pair: %s", err)
		}

		ca := x509.NewCertPool()
		caBytes, err := os.ReadFile(configValue.CaPath)
		if err != nil {
			log.Fatalf("failed to read ca cert %q: %v", configValue.CaPath, err)
		}
		if ok := ca.AppendCertsFromPEM(caBytes); !ok {
			log.Fatalf("failed to parse %q", configValue.CaPath)
		}

		tlsConfig := &tls.Config{
			ServerName:   serverName,
			Certificates: []tls.Certificate{cert},
			RootCAs:      ca,
		}

		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		if err != nil {
			fmt.Print(err)
			return nil, err
		}
		return conn, nil
	}
}

func main() {
	configValue, err := config.GetConfig()
	if err != nil {
		log.Fatal(err.Error())
	}

	addr := fmt.Sprintf("%s:%d", configValue.Clients.GRPCHost, configValue.Clients.GRPCPort)
	clientConn, err := newGrpcConn(addr, configValue.Clients.ServerName, configValue)
	if err != nil {
		log.Fatal(err)
	}
	defer clientConn.Close()

	clientRepository := clients.NewGRPCClientsRepository(clientConn)

	addr = fmt.Sprintf("%s:%d", configValue.Users.GRPCHost, configValue.Users.GRPCPort)
	userConn, err := newGrpcConn(addr, configValue.Users.ServerName, configValue)
	if err != nil {
		log.Fatal(err)
	}
	defer userConn.Close()
	userRepository := users.NewGRPCUsersRepository(userConn)

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

	// TODO: get timeout from client and request
	idTokenJWTEncoder := oidcencoding.NewIDTokenJWTEncoder(kmsvalue, configValue.Issuer, 2*60*60, idTokenKey.GetID())                // 2 hours
	accessTokenEncoder := oidcencoding.NewAccessTokenJWTEncoder(kmsvalue, configValue.Issuer, 50*60, accessTokenKey.GetID())         // 50 minutes
	refreshTokenEncoder := oidcencoding.NewRefreshTokenJWTEncoder(kmsvalue, configValue.Issuer, 2*24*60*50, refreshTokenKey.GetID()) // 2 days

	tmpl := template.Must(template.ParseFiles(fmt.Sprintf("%s/authorize.html", configValue.TemplatesDir)))
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
	// TODO: CORS
	// Authentication Request MUST support the use of the HTTP GET and POST
	r.GET("/oidc/auth", CSPHandler(authHandler.Handle))
	r.POST("/oidc/auth", CSPHandler(authHandler.Handle))

	r.POST("/oidc/token", CORSHandlerMiddleware(NoCacheHandler(tokenHandler.Handle)))
	r.OPTIONS("/oidc/token", CORSHandler)
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

	addr = fmt.Sprintf("%s:%d", configValue.HTTPHost, configValue.HTTPPort)
	log.Printf("Listening %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}
