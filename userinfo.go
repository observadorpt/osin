package osin

import (
	"errors"
	"net/http"
	"strings"
)

type Claims map[string]interface{}

// func (c *Claims) Set(key string, value string) {

// }

// Return sets of claim by scope name
type ClaimManager interface {
	// if parameter empty, return the default claim
	GetClaims(scope string, user interface{}) Claims
	AvailableScope() []string
}

func (s *Server) HandleUserInfoRequest(w *Response, r *http.Request) {
	// Only support POST and GET request
	if r.Method != "GET" && r.Method != "POST" && r.Method != "OPTIONS" {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = errors.New("Request must be GET or POST")
		return
	}
	// Get bearer access token
	bearerAuth := CheckBearerAuth(r)
	if bearerAuth == nil {
		// Invalid token error
		w.SetError(E_INVALID_TOKEN, "Invalid Token")
		return
	}
	acessData, err := w.Storage.LoadAccess(bearerAuth.Code)
	if err != nil {
		w.SetError(E_SERVER_ERROR, "")
		w.InternalError = err
		return
	}
	if acessData.IsExpired() {
		w.SetError(E_INVALID_TOKEN, "The Access Token expired")
		return
	}
	var userId = acessData.UserData.(string)
	acessData.UserData, _ = s.UserStorage.GetUser(userId)
	w.Output["sub"] = acessData.UserData.(User).GetSub()
	scopes := strings.Split(acessData.Scope, " ")
	for _, scope := range scopes {
		claims := s.ClaimManager.GetClaims(scope, acessData.UserData)
		for k, v := range claims {
			w.Output[k] = v
		}
	}
}
