package openidconnect

import (
	"crypto/hmac"
	"crypto/sha256"
)

var secret = []byte("SECRET")
var mac = hmac.New(sha256.New, secret)
