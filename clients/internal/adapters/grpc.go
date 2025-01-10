package adapters

import (
	"context"
	"errors"

	pb "github.com/G5Olivieri/luau/clients/clients"
	"github.com/G5Olivieri/luau/clients/internal"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type GRPCServer struct {
	impl internal.ClientsService
	pb.UnimplementedClientServiceServer
}

func (s *GRPCServer) Create(ctx context.Context, request *pb.CreateClientRequest) (*pb.Client, error) {
	urls, err := urisStringToURLs(request.GetRedirectUris())

	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	clientCreated, err := s.impl.Create(ctx, &internal.CreateClientRequest{
		Name:         request.GetName(),
		RedirectURIs: urls,
	})

	if err != nil {
		return nil, status.Errorf(codes.Internal, "internal: %v", err)
	}

	return &pb.Client{
		ID:           clientCreated.ID.String(),
		Name:         clientCreated.Name,
		RedirectUris: urisURLToStrings(clientCreated.RedirectURIs),
	}, nil
}

func (s *GRPCServer) Update(ctx context.Context, request *pb.Client) (*pb.Client, error) {
	id, err := uuid.Parse(request.GetID())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "uuid malformed: %v", err)
	}

	urls, err := urisStringToURLs(request.GetRedirectUris())

	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	clientUpdated, err := s.impl.Update(ctx, &internal.Client{
		ID:           id,
		Name:         request.GetName(),
		RedirectURIs: urls,
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
		RedirectUris: urisURLToStrings(clientUpdated.RedirectURIs),
	}, nil
}

func (s *GRPCServer) DeleteByID(ctx context.Context, providedID *wrapperspb.StringValue) (*emptypb.Empty, error) {
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

func (s *GRPCServer) GetByID(ctx context.Context, providedID *wrapperspb.StringValue) (*pb.Client, error) {
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
		RedirectUris: urisURLToStrings(client.RedirectURIs),
	}, nil
}
