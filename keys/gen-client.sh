openssl req -new -out client_csr.pem -key client_private_key.pem -nodes -sha256 -config ./openssl.cnf -reqexts test_client -subj /C=BR/ST=SP/L=SP/O=Luau Org./CN=client
openssl x509 -req -in client_csr.pem -CAkey ca_private_key.pem -CA ca_cert.pem -CAcreateserial -out client_cert.pem -days 3650 -extfile ./openssl.cnf -extensions test_client -sha256
