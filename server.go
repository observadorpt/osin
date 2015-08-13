package osin

import (
	"time"
)

// Server is an OAuth2 implementation
type Server struct {
	Config            *ServerConfig
	Storage           Storage
	UserStorage       UserStorage
	AuthorizeTokenGen AuthorizeTokenGen
	AccessTokenGen    AccessTokenGen
	Now               func() time.Time
	ClaimManager      ClaimManager
}

// NewServer creates a new server instance
func NewServer(config *ServerConfig, storage Storage) *Server {
	return &Server{
		Config:            config,
		Storage:           storage,
		AuthorizeTokenGen: &AuthorizeTokenGenDefault{},
		AccessTokenGen:    &AccessTokenGenDefault{},
		Now:               time.Now,
	}
}

// NewResponse creates a new response for the server
func (s *Server) NewResponse() *Response {
	r := NewResponse(s.Storage)
	r.ErrorStatusCode = s.Config.ErrorStatusCode
	return r
}
