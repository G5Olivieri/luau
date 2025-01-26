module github.com/G5Olivieri/luau

go 1.23.2

require (
	github.com/G5Olivieri/luau/clients v0.0.0-00010101000000-000000000000
	github.com/G5Olivieri/luau/jose v0.0.0-00010101000000-000000000000
	github.com/G5Olivieri/luau/kms v0.0.0-00010101000000-000000000000
	github.com/google/uuid v1.6.0
	github.com/julienschmidt/httprouter v1.3.0
	google.golang.org/grpc v1.70.0
	google.golang.org/protobuf v1.36.2
)

require (
	github.com/G5Olivieri/luau/users v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241202173237-19429a94021a // indirect
)

replace github.com/G5Olivieri/luau/clients => ./clients

replace github.com/G5Olivieri/luau/users => ./users

replace github.com/G5Olivieri/luau/jose => ./jose

replace github.com/G5Olivieri/luau/kms => ./kms
