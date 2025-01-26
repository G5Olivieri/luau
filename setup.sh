client=$1
cred=$(echo "$client" | jq -r '"\(.id):\(.secret)"')
token=$(curl -u "$cred" "http://localhost:8080/oidc/token" -X POST -d grant_type=client_credentials  | jq -r ".access_token")

echo -e "demo"
curl "http://localhost:5050/api" \
    -X POST \
    -d '{"name":{"default":"Demo"},"redirect_uris": ["http://localhost:3000/callback.html"]}' \
    -H 'content-type: application/json' \
    -H "Authorization: Bearer $token"

echo -e "\n\nusers"
curl "http://localhost:5050/api" \
    -X POST \
    -d '{"name":{"default":"Users Swagger"},"redirect_uris": ["http://localhost:5052/swagger/oauth2-redirect.html"]}' \
    -H 'content-type: application/json' \
    -H "Authorization: Bearer $token"

echo -e "\n\nkms"
curl "http://localhost:5050/api" \
    -X POST \
    -d '{"name":{"default":"KMS Swagger"},"redirect_uris": ["http://localhost:5054/swagger/oauth2-redirect.html"]}' \
    -H 'content-type: application/json' \
    -H "Authorization: Bearer $token"

echo -e "\n\ncreate glayson user"
curl "http://localhost:5052/api" \
    -X POST \
    -d '{"username":"glayson","password":"glayson"}' \
    -H 'content-type: application/json' \
    -H "Authorization: Bearer $token"
