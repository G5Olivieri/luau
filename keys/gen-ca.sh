openssl genpkey -algorithm ed25519 -out ca_private_key.pem
openssl req -x509 -key ca_private_key.pem -out ca_cert.pem -subj "/C=BR/ST=SP/L=SP/O=Luau Org./CN=luau_ca" -config ./openssl.cnf -extensions test_ca -nodes -sha256 -days 3650
