package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"

	pb "github.com/G5Olivieri/luau/clients/clients"
	"github.com/G5Olivieri/luau/clients/internal"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

type server struct {
	impl internal.ClientsService
	pb.UnimplementedClientServiceServer
}

func (s *server) Create(ctx context.Context, request *pb.CreateClientRequest) (*pb.Client, error) {
	clientCreated, err := s.impl.Create(ctx, &internal.CreateClientRequest{
		Name:         request.GetName(),
		RedirectURIs: request.GetRedirectUris(),
	})

	if err != nil {
		return nil, status.Errorf(codes.Internal, "internal: %v", err)
	}

	return &pb.Client{
		ID:           clientCreated.ID.String(),
		Name:         clientCreated.Name,
		RedirectUris: clientCreated.RedirectURIs,
	}, nil
}

func (s *server) Update(ctx context.Context, request *pb.Client) (*pb.Client, error) {
	id, err := uuid.Parse(request.GetID())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "uuid malformed: %v", err)
	}

	clientUpdated, err := s.impl.Update(ctx, &internal.Client{
		ID:           id,
		Name:         request.GetName(),
		RedirectURIs: request.GetRedirectUris(),
	})

	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "not found")
		}
		return nil, status.Errorf(codes.Internal, "internal: %v", err)
	}

	return &pb.Client{
		ID:           clientUpdated.ID.String(),
		Name:         clientUpdated.Name,
		RedirectUris: clientUpdated.RedirectURIs,
	}, nil
}

func (s *server) DeleteByID(ctx context.Context, providedID *wrapperspb.StringValue) (*emptypb.Empty, error) {
	id, err := uuid.Parse(providedID.GetValue())

	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "uuid malformed: %v", err)
	}

	if err = s.impl.DeleteByID(ctx, &id); err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "not found")
		}
		return nil, status.Errorf(codes.Internal, "internal: %v", err)
	}

	return &emptypb.Empty{}, nil
}

func (s *server) GetByID(ctx context.Context, providedID *wrapperspb.StringValue) (*pb.Client, error) {
	id, err := uuid.Parse(providedID.GetValue())

	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "uuid malformed: %v", err)
	}

	client, err := s.impl.GetByID(ctx, &id)
	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "not found")
		}
		return nil, status.Errorf(codes.Internal, "internal: %v", err)
	}

	return &pb.Client{
		ID:           client.ID.String(),
		Name:         client.Name,
		RedirectUris: client.RedirectURIs,
	}, nil
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen %v\n", err)
	}
	s := grpc.NewServer()
	server := server{
		impl: internal.NewInMemoryClientsService(),
	}

	pb.RegisterClientServiceServer(s, &server)

	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve %v", err)
	}
}
