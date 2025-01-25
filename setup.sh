client=$1
cred=$(echo "$client" | jq -r '"\(.id):\(.secret)"')
token=$(curl -u "$cred" "http://localhost:8080/oidc/token" -X POST -d grant_type=client_credentials  | jq -r ".access_token")

curl "http://localhost:5050/api" \
    -X POST \
    -d '{"name":{"default":"Demo"},"redirect_uris": ["http://localhost:3000/callback.html"]}' \
    -H 'content-type: application/json' \
    -H "Authorization: Bearer $token"

curl "http://localhost:5052/api" \
    -X POST \
    -d '{"username":"glayson","password":"glayson"}' \
    -H 'content-type: application/json' \
    -H "Authorization: Bearer $token"
