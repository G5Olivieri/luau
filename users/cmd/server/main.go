package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/G5Olivieri/luau/users/internal"
	"github.com/G5Olivieri/luau/users/internal/adapters"
	pb "github.com/G5Olivieri/luau/users/users"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

var (
	hostGRPC       = flag.String("grpc_host", "", "The gRPC server host")
	portGRPC       = flag.Int("grpc_port", 50053, "The gRPC server port")
	hostHTTP       = flag.String("http_host", "", "The HTTP server host")
	portHTTP       = flag.Int("http_port", 50054, "The HTTP server port")
	caFile         = flag.String("ca", "", "CA file (PEM)")
	certFile       = flag.String("cert", "", "Certificate file (PEM)")
	privateKeyFile = flag.String("pkey", "", "Privatey key file (PEM)")
	authHost       = flag.String("auth_host", "", "Auth host")
	g              errgroup.Group
)

func startGRPC(impl internal.UsersService, host string, port int) error {
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Fatalf("failed to listen %v\n", err)
	}

	cert, err := tls.LoadX509KeyPair(*certFile, *privateKeyFile)
	if err != nil {
		log.Fatalf("failed to load key pair: %s", err)
	}

	ca := x509.NewCertPool()
	caBytes, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("failed to read ca cert %q: %v", *caFile, err)
	}
	if ok := ca.AppendCertsFromPEM(caBytes); !ok {
		log.Fatalf("failed to parse %q", *caFile)
	}

	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    ca,
	}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))

	server := adapters.NewGRPCServer(impl)

	pb.RegisterUserServiceServer(s, server)

	reflection.Register(s)
	log.Printf("GRPC server listening at %v", lis.Addr())
	return s.Serve(lis)
}

func startHTTP(impl internal.UsersService, host string, port int) error {
	handler := adapters.NewRestHTTPHandler(impl, *authHost)
	server := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", host, port),
		Handler:        handler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Printf("HTTP server listening at %v", server.Addr)
	return server.ListenAndServe()
}

func main() {
	flag.Parse()
	if *caFile == "" || *privateKeyFile == "" || *certFile == "" || *authHost == "" {
		log.Fatal("CA, private key and cert are required")
	}
	// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	// The 32-sized ouput can be used as AES-256 key
	hasher := internal.NewArgon2PasswordHasher(1, 46*1024, 1, 32)
	encoder := internal.NewEncodedArgon2PasswordHasher(hasher)
	internalImpl := internal.NewInMemoryUsersService(encoder)
	g.Go(func() error { return startGRPC(internalImpl, *hostGRPC, *portGRPC) })
	g.Go(func() error { return startHTTP(internalImpl, *hostHTTP, *portHTTP) })
	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}
