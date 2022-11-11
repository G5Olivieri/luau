package openidconnect

import (
	"os"
	"strconv"
)

var (
	expiresIn, _ = strconv.ParseUint(os.Getenv("EXPIRES_IN"), 10, 32)
	issuer       = os.Getenv("ISSUER")
	secret       = []byte(os.Getenv("SECRET"))
)
