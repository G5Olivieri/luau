package clients

import (
	"context"

	pb "github.com/G5Olivieri/luau/clients/clients"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type GRPCClientsRepository struct {
	grpcClient pb.ClientServiceClient
}

func NewGRPCClientsRepository(conn *grpc.ClientConn) *GRPCClientsRepository {
	clientServiceClient := pb.NewClientServiceClient(conn)
	return &GRPCClientsRepository{
		grpcClient: clientServiceClient,
	}
}

func (r *GRPCClientsRepository) GetByID(ctx context.Context, id string) (*Client, error) {
	client, err := r.grpcClient.GetByID(ctx, &wrapperspb.StringValue{Value: id})

	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &Client{
		ID:             client.ID,
		RawRedirectURI: client.RedirectUris[0],
	}, nil
}
