openssl genpkey -algorithm ed25519 -out server_private_key.pem
openssl req -new -out server_csr.pem -key server_private_key.pem -nodes -sha256 -config ./openssl.cnf -reqexts test_server -subj "/C=BR/ST=SP/L=SP/O=Luau Org./CN=server"
openssl x509 -req -in server_csr.pem -CAkey ca_private_key.pem -CA ca_cert.pem -CAcreateserial -out server_cert.pem -days 3650 -extfile ./openssl.cnf -extensions test_server -sha256
