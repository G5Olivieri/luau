package openidconnect

import (
	"errors"
	"strings"
)

type AuthorizationCodeRequest struct {
	ResponseType string `form:"response_type" binding:"required"`
	Scope        string `form:"scope"         binding:"required"`
}

func validateAuthorizationRequest(request AuthorizationCodeRequest) error {
	if request.ResponseType != "code" {
		return errors.New("Invalid response_type")
	}

	if !strings.Contains(request.Scope, "openid") {
		return errors.New("Invalid scope")
	}

	return nil
}
