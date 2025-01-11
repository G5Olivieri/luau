package adapters

import (
	"context"
	"errors"
	"time"

	"github.com/G5Olivieri/luau/users/internal"
	pb "github.com/G5Olivieri/luau/users/users"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type GRPCServer struct {
	impl internal.UsersService
	pb.UnimplementedUserServiceServer
}

func (s *GRPCServer) Create(ctx context.Context, request *pb.CreateUserRequest) (*pb.User, error) {
	var lastLogin *time.Time

	if request.GetLastLogin() != 0 {
		lastLoginV := time.Unix(request.GetLastLogin(), 0)
		lastLogin = &lastLoginV
	}

	userCreated, err := s.impl.Create(ctx, &internal.CreateUserRequest{
		Username:  request.GetUsername(),
		Password:  request.GetPassword(),
		LastLogin: lastLogin,
	})

	if err != nil {
		return nil, status.Errorf(codes.Internal, "internal: %v", err)
	}

	return &pb.User{
		ID:        userCreated.ID.String(),
		Username:  userCreated.Username,
		Password:  userCreated.Password,
		LastLogin: request.GetLastLogin(),
	}, nil
}

func (s *GRPCServer) Update(ctx context.Context, request *pb.User) (*pb.User, error) {
	id, err := uuid.Parse(request.GetID())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "uuid malformed: %v", err)
	}

	var lastLogin *time.Time
	if request.GetLastLogin() != 0 {
		lastLoginV := time.Unix(request.GetLastLogin(), 0)
		lastLogin = &lastLoginV
	}

	userUpdated, err := s.impl.Update(ctx, &internal.User{
		ID:        id,
		Username:  request.GetUsername(),
		Password:  request.GetPassword(),
		LastLogin: lastLogin,
	})

	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "not found")
		}
		return nil, status.Errorf(codes.Internal, "internal: %v", err)
	}

	return &pb.User{
		ID:        userUpdated.ID.String(),
		Username:  userUpdated.Username,
		Password:  userUpdated.Password,
		LastLogin: request.GetLastLogin(),
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

func (s *GRPCServer) GetByID(ctx context.Context, providedID *wrapperspb.StringValue) (*pb.User, error) {
	id, err := uuid.Parse(providedID.GetValue())

	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "uuid malformed: %v", err)
	}

	user, err := s.impl.GetByID(ctx, &id)
	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "not found")
		}
		return nil, status.Errorf(codes.Internal, "internal: %v", err)
	}

	var lastLogin int64
	if user.LastLogin != nil {
		lastLogin = user.LastLogin.Unix()
	}

	return &pb.User{
		ID:        user.ID.String(),
		Username:  user.Username,
		Password:  user.Password,
		LastLogin: lastLogin,
	}, nil
}

func (s *GRPCServer) GetByUsername(ctx context.Context, username *wrapperspb.StringValue) (*pb.User, error) {
	user, err := s.impl.GetByUsername(ctx, username.GetValue())
	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "not found")
		}
		return nil, status.Errorf(codes.Internal, "internal: %v", err)
	}

	var lastLogin int64
	if user.LastLogin != nil {
		lastLogin = user.LastLogin.Unix()
	}

	return &pb.User{
		ID:        user.ID.String(),
		Username:  user.Username,
		Password:  user.Password,
		LastLogin: lastLogin,
	}, nil
}

func (s *GRPCServer) GetByUsernamePassword(ctx context.Context, usernamePassword *pb.UsernamePassword) (*pb.User, error) {
	user, err := s.impl.GetByUsernamePassword(ctx, usernamePassword.GetUsername(), usernamePassword.GetPassword())
	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "not found")
		}
		return nil, status.Errorf(codes.Internal, "internal: %v", err)
	}

	var lastLogin int64
	if user.LastLogin != nil {
		lastLogin = user.LastLogin.Unix()
	}

	return &pb.User{
		ID:        user.ID.String(),
		Username:  user.Username,
		Password:  user.Password,
		LastLogin: lastLogin,
	}, nil
}

func (s *GRPCServer) List(ctx context.Context, request *pb.LimitOffset) (*pb.Users, error) {
	users, err := s.impl.List(ctx, int(request.GetLimit()), int(request.GetOffset()))

	if err != nil {
		return nil, status.Errorf(codes.Internal, "internal: %v", err)
	}

	responseUsers := make([]*pb.User, 0, len(users))
	for _, user := range users {
		var lastLogin int64
		if user.LastLogin != nil {
			lastLogin = user.LastLogin.Unix()
		}
		responseUsers = append(responseUsers, &pb.User{
			ID:        user.ID.String(),
			Username:  user.Username,
			Password:  user.Password,
			LastLogin: lastLogin,
		})
	}

	return &pb.Users{
		Users: responseUsers,
	}, nil
}
