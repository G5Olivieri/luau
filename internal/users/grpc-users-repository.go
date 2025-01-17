package users

import (
	"context"

	pb "github.com/G5Olivieri/luau/users/users"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type GRPCUsersRepository struct {
	grpcUser pb.UserServiceClient
}

func NewGRPCUsersRepository(conn *grpc.ClientConn) *GRPCUsersRepository {
	userServiceUser := pb.NewUserServiceClient(conn)
	return &GRPCUsersRepository{
		grpcUser: userServiceUser,
	}
}

func (r *GRPCUsersRepository) GetByID(ctx context.Context, id string) (*User, error) {
	user, err := r.grpcUser.GetByID(ctx, &wrapperspb.StringValue{Value: id})

	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &User{
		ID:        user.GetID(),
		Username:  user.GetUsername(),
		Password:  user.GetPassword(),
		LastLogin: user.GetLastLogin(),
	}, nil
}

func (r *GRPCUsersRepository) GetByUsername(ctx context.Context, username string) (*User, error) {
	user, err := r.grpcUser.GetByUsername(ctx, &wrapperspb.StringValue{Value: username})

	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &User{
		ID:        user.GetID(),
		Username:  user.GetUsername(),
		Password:  user.GetPassword(),
		LastLogin: user.GetLastLogin(),
	}, nil
}

func (r *GRPCUsersRepository) GetByUsernamePassword(ctx context.Context, username, password string) (*User, error) {
	user, err := r.grpcUser.GetByUsernamePassword(ctx, &pb.UsernamePassword{Username: username, Password: password})

	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &User{
		ID:        user.GetID(),
		Username:  user.GetUsername(),
		Password:  user.GetPassword(),
		LastLogin: user.GetLastLogin(),
	}, nil
}

func (r *GRPCUsersRepository) Update(ctx context.Context, user *User) (*User, error) {
	res, err := r.grpcUser.Update(ctx, &pb.User{
		ID:        user.ID,
		Username:  user.Username,
		Password:  user.Password,
		LastLogin: user.LastLogin,
	})

	if err != nil {
		return nil, err
	}
	return &User{
		ID:        res.GetID(),
		Username:  res.GetID(),
		Password:  res.GetPassword(),
		LastLogin: res.GetLastLogin(),
	}, nil
}
