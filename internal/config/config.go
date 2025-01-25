package config

import (
	"fmt"
	"os"
	"strconv"
)

type ClientsConfig struct {
	ServerName string
	GRPCHost   string
	GRPCPort   int
	HTTPHost   string
	HTTPPort   int
}

type UsersConfig struct {
	ServerName string
	GRPCHost   string
	GRPCPort   int
	HTTPHost   string
	HTTPPort   int
}

type Config struct {
	Issuer                   string
	CaPath                   string
	ClientCertPath           string
	ClientCertPrivateKeyPath string
	GrpcInsecure             bool
	HTTPHost                 string
	HTTPPort                 int
	Clients                  ClientsConfig
	Users                    UsersConfig
	TemplatesDir             string
}

// TODO: config files (INI, JSON, YAML, TOML)
func GetConfig() (Config, error) {
	config := Config{}
	issuer := os.Getenv("ISSUER")
	if issuer == "" {
		return config, fmt.Errorf("environment ISSUER is missing")
	}

	httpHost := os.Getenv("HTTP_HOST")
	if httpHost == "" {
		return config, fmt.Errorf("environment HTTP_HOST is missing")
	}
	config.HTTPHost = httpHost

	httpPort, err := strconv.Atoi(os.Getenv("HTTP_PORT"))

	if err != nil {
		return config, fmt.Errorf("environment HTTP_PORT: %v", err)
	}
	config.HTTPPort = httpPort

	caPath := os.Getenv("CA_CERT")
	if caPath == "" {
		return config, fmt.Errorf("environment CA_CERT is missing")
	}
	config.CaPath = caPath

	clientCert := os.Getenv("CLIENT_CERT")
	if clientCert == "" {
		return config, fmt.Errorf("environment CLIENT_CERT is missing")
	}
	config.ClientCertPath = clientCert

	clientCertPrivateKey := os.Getenv("CLIENT_PRIVATE_KEY")
	if clientCertPrivateKey == "" {
		return config, fmt.Errorf("environment CLIENT_PRIVATE_KEY is missing")
	}
	config.ClientCertPrivateKeyPath = clientCertPrivateKey

	clientsHttpHost := os.Getenv("CLIENTS_HTTP_HOST")
	if clientsHttpHost == "" {
		return config, fmt.Errorf("environment CLIENTS_HTTP_HOST is missing")
	}

	clientsHttpPort, err := strconv.Atoi(os.Getenv("CLIENTS_HTTP_PORT"))
	if err != nil {
		return config, fmt.Errorf("environment CLIENTS_HTTP_PORT: %v", err)
	}

	clientsGrpcHost := os.Getenv("CLIENTS_GRPC_HOST")
	if clientsHttpHost == "" {
		return config, fmt.Errorf("environment CLIENTS_GRPC_HOST is missing")
	}

	clientsGrpcPort, err := strconv.Atoi(os.Getenv("CLIENTS_GRPC_PORT"))
	if err != nil {
		return config, fmt.Errorf("environment CLIENTS_GRPC_PORT: %v", err)
	}

	clientsServerName := os.Getenv("CLIENTS_SERVER_NAME")
	if clientsServerName == "" {
		return config, fmt.Errorf("environment CLIENTS_SERVER_NAME is missing")
	}

	config.Clients = ClientsConfig{
		ServerName: clientsServerName,
		HTTPHost:   clientsHttpHost,
		HTTPPort:   clientsHttpPort,
		GRPCHost:   clientsGrpcHost,
		GRPCPort:   clientsGrpcPort,
	}

	usersHttpHost := os.Getenv("USERS_HTTP_HOST")
	if usersHttpHost == "" {
		return config, fmt.Errorf("environment USERS_HTTP_HOST is missing")
	}

	usersHttpPort, err := strconv.Atoi(os.Getenv("USERS_HTTP_PORT"))
	if err != nil {
		return config, fmt.Errorf("environment USERS_HTTP_PORT: %v", err)
	}

	usersGrpcHost := os.Getenv("USERS_GRPC_HOST")
	if clientsHttpHost == "" {
		return config, fmt.Errorf("environment USERS_HTTP_HOST is missing")
	}

	usersGrpcPort, err := strconv.Atoi(os.Getenv("USERS_GRPC_PORT"))
	if err != nil {
		return config, fmt.Errorf("environment USERS_GRPC_PORT: %v", err)
	}

	usersServerName := os.Getenv("USERS_SERVER_NAME")
	if usersServerName == "" {
		return config, fmt.Errorf("environment USERS_SERVER_NAME is missing")
	}
	config.Users = UsersConfig{
		ServerName: usersServerName,
		HTTPHost:   usersHttpHost,
		HTTPPort:   usersHttpPort,
		GRPCHost:   usersGrpcHost,
		GRPCPort:   usersGrpcPort,
	}

	templatesDir := os.Getenv("TEMPLATES_DIR")
	if templatesDir == "" {
		return config, fmt.Errorf("environment TEMPLATES_DIR is missing")
	}
	config.TemplatesDir = templatesDir

	config.GrpcInsecure = os.Getenv("GRPC_INSECURE") == "true"

	return config, nil
}
