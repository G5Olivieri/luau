package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	pb "github.com/G5Olivieri/luau/clients/clients"
	"github.com/G5Olivieri/luau/clients/internal"
	"github.com/G5Olivieri/luau/clients/internal/adapters"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	portGRPC = flag.Int("port_grpc", 50051, "The server port")
	portHTTP = flag.Int("port_http", 50052, "The server port")
	g        errgroup.Group
)

func startGRPC(impl internal.ClientsService) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *portGRPC))
	if err != nil {
		log.Fatalf("failed to listen %v\n", err)
	}
	s := grpc.NewServer()

	server := adapters.NewGRPCServer(impl)

	pb.RegisterClientServiceServer(s, server)

	reflection.Register(s)
	log.Printf("GRPC server listening at %v", lis.Addr())
	return s.Serve(lis)
}

func startHTTP(impl internal.ClientsService) error {
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

// @title           Swagger Example API
// @version         1.0
// @description     This is a sample server celler server.
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.swagger.io/support
// @contact.email  support@swagger.io

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8080
// @BasePath  /

// @externalDocs.description  OpenAPI
// @externalDocs.url          https://swagger.io/resources/open-api/
func main() {
	flag.Parse()
	internalImpl := internal.NewInMemoryClientsService()
	g.Go(func() error { return startGRPC(internalImpl) })
	g.Go(func() error { return startHTTP(internalImpl) })
	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}
