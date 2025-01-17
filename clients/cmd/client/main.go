package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	pb "github.com/G5Olivieri/luau/clients/clients"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type createClient struct {
	Name         map[string]string `json:"name"`
	RedirectURIs []string          `json:"redirect_uris"`
}

type client struct {
	ID           string            `json:"id"`
	Name         map[string]string `json:"name"`
	RedirectURIs []string          `json:"redirect_uris"`
}

var (
	addr           = flag.String("addr", ":50051", "The server addr")
	filePath       = flag.String("file", "", "data file")
	caFile         = flag.String("ca", "", "CA file (PEM)")
	certFile       = flag.String("cert", "", "Certificate file (PEM)")
	privateKeyFile = flag.String("pkey", "", "Privatey key file (PEM)")
	insecure       = flag.Bool("insecure", false, "Insecure gRPC connection")
)

func toClient(c *pb.Client) client {
	return client{
		ID:           c.GetID(),
		Name:         c.GetName(),
		RedirectURIs: c.GetRedirectUris(),
	}
}

func newGrpcConn() (conn *grpc.ClientConn, err error) {
	if *insecure {
		conn, err = grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
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
			ServerName:   "server.luau.org",
			Certificates: []tls.Certificate{cert},
			RootCAs:      ca,
		}

		conn, err = grpc.NewClient(*addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}
	if err != nil {
		fmt.Print(err)
		return nil, err
	}
	return conn, nil
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("missing cmd")
		os.Exit(1)
	}
	if *caFile == "" || *certFile == "" || *privateKeyFile == "" {
		log.Fatal("missing ca, cert or pkey")
	}
	cmd, args := args[0], args[1:]
	switch cmd {
	case "create":
		if *filePath == "" {
			fmt.Println("missing file")
			os.Exit(1)
		}
		file, err := os.Open(*filePath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer file.Close()

		var data createClient
		if err = json.NewDecoder(file).Decode(&data); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		conn, err := newGrpcConn()
		if err != nil {
			os.Exit(1)
		}
		defer conn.Close()
		clientServiceClient := pb.NewClientServiceClient(conn)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		created, err := clientServiceClient.Create(ctx, &pb.CreateClientRequest{
			Name:         data.Name,
			RedirectUris: data.RedirectURIs,
		})
		if err != nil {
			fmt.Print(err)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(toClient(created))
		os.Exit(0)
	case "list":
		listCmd := flag.NewFlagSet("list", flag.ExitOnError)
		limit := listCmd.Int("limit", 10, "limit")
		offset := listCmd.Int("offset", 0, "offset")
		listCmd.Parse(args)

		conn, err := newGrpcConn()
		if err != nil {
			os.Exit(1)
		}
		defer conn.Close()
		clientServiceClient := pb.NewClientServiceClient(conn)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		clients, err := clientServiceClient.List(ctx, &pb.LimitOffset{
			Limit:  int32(*limit),
			Offset: int32(*offset),
		})
		if err != nil {
			fmt.Print(err)
			os.Exit(1)
		}
		output := make([]client, 0, len(clients.GetClients()))
		for _, v := range clients.GetClients() {
			output = append(output, toClient(v))
		}
		json.NewEncoder(os.Stdout).Encode(output)
		os.Exit(0)
	case "get_by_id":
	case "update":
	case "delete_by_id":
	default:
		fmt.Println("invalid cmd: create, list, get_by_id, update")
	}
}
