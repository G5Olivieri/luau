up:
	docker compose up -d

down:
	docker compose kill
	docker compose rm -f

logs:
	docker compose logs -f

clean-protoc:
	rm jose/jose/*.go
	rm clients/clients/*.go
	rm users/users/*.go

protoc: protoc-jose protoc-clients protoc-users protoc-kms

protoc-clients: clients/clients/client.pb.go clients/clients/client_service.pb.go clients/clients/client_service_grpc.pb.go

clients/clients/client.pb.go:
	protoc -I./include -I./jose -I./clients/clients --go_out=clients/clients --go_opt=paths=source_relative --go-grpc_out=clients/clients --go-grpc_opt=paths=source_relative clients/clients/client.proto

clients/clients/client_service.pb.go:
	protoc -I./include -I./jose -I./clients/clients --go_out=clients/clients --go_opt=paths=source_relative --go-grpc_out=clients/clients --go-grpc_opt=paths=source_relative clients/clients/client_service.proto

clients/clients/client_service_grpc.pb.go: clients/clients/client_service.pb.go

protoc-users: users/users/user.pb.go users/users/user_service.pb.go users/users/user_service_grpc.pb.go

users/users/user.pb.go:
	protoc -I./include -I./jose -I./users/users --go_out=users/users --go_opt=paths=source_relative --go-grpc_out=users/users --go-grpc_opt=paths=source_relative users/users/user.proto

users/users/user_service.pb.go:
	protoc -I./include -I./jose -I./users/users --go_out=users/users --go_opt=paths=source_relative --go-grpc_out=users/users --go-grpc_opt=paths=source_relative users/users/user_service.proto

protoc-kms: kms/kms/kms_service.pb.go

kms/kms/kms_service.pb.go: kms/kms/kms_service.proto
	protoc -I./include -I./jose -I./kms/kms --go_out=kms/kms --go_opt=paths=source_relative --go-grpc_out=kms/kms --go-grpc_opt=paths=source_relative kms/kms/kms_service.proto

protoc-jose: jose/jose/jwk.pb.go

jose/jose/jwk.pb.go: jose/jose/jwk.proto
	protoc -I./include -I./jose --go_out=jose --go_opt=paths=source_relative --go-grpc_out=jose --go-grpc_opt=paths=source_relative jose/jose/jwk.proto

swagger: swagger-clients swagger-users swagger-kms

swagger-clients: clients/docs/swagger.yaml

clients/docs/swagger.yaml: clients/internal/adapters/rest.go
	swag init -g rest.go -d clients/internal/adapters -o clients/docs

swagger-users: users/docs/swagger.yaml

users/docs/swagger.yaml: users/internal/adapters/rest.go
	swag init -g rest.go -d users/internal/adapters -o users/docs

swagger-kms: kms/docs/swagger.yaml

kms/docs/swagger.yaml: kms/internal/adapters/rest.go
	swag init -g rest.go -d kms/internal/adapters -o kms/docs --parseDependency

