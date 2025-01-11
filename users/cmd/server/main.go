package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/G5Olivieri/luau/users/internal"
	"github.com/G5Olivieri/luau/users/internal/adapters"
	pb "github.com/G5Olivieri/luau/users/users"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	portGRPC = flag.Int("port_grpc", 50053, "The server port")
	portHTTP = flag.Int("port_http", 50054, "The server port")
	g        errgroup.Group
)

func startGRPC(impl internal.UsersService) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *portGRPC))
	if err != nil {
		log.Fatalf("failed to listen %v\n", err)
	}
	s := grpc.NewServer()

	server := adapters.NewGRPCServer(impl)

	pb.RegisterUserServiceServer(s, server)

	reflection.Register(s)
	log.Printf("GRPC server listening at %v", lis.Addr())
	return s.Serve(lis)
}

func startHTTP(impl internal.UsersService) error {
	handler := adapters.NewRestHTTPHandler(impl)
	server := &http.Server{
		Addr:           fmt.Sprintf(":%d", *portHTTP),
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
	// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	// The 32-sized ouput can be used as AES-256 key
	hasher := internal.NewArgon2PasswordHasher(1, 46*1024, 1, 32)
	encoder := internal.NewEncodedArgon2PasswordHasher(hasher)
	internalImpl := internal.NewInMemoryUsersService(encoder)
	g.Go(func() error { return startGRPC(internalImpl) })
	g.Go(func() error { return startHTTP(internalImpl) })
	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}
