package server

import (
	"github.com/GymWorkoutApp/gwa_auth/constants"
	"net/http"
	"time"
)

// Config configuration parameters
type Config struct {
	TokenType             string                // token type
	AllowGetAccessRequest bool                  // to allow GET requests for the token
	AllowedResponseTypes  []constants.ResponseType // allow the authorization type
	AllowedGrantTypes     []constants.GrantType    // allow the grant type
}

// NewConfig create to configuration instance
func NewConfig() *Config {
	return &Config{
		TokenType:            "Bearer",
		AllowedResponseTypes: []constants.ResponseType{constants.Code, constants.Token},
		AllowedGrantTypes: []constants.GrantType{
			constants.AuthorizationCode,
			constants.PasswordCredentials,
			constants.ClientCredentials,
			constants.Refreshing,
		},
	}
}

// AuthorizeRequest authorization request
type AuthorizeRequest struct {
	ResponseType   constants.ResponseType
	ClientID       string
	Scope          string
	RedirectURI    string
	State          string
	UserID         string
	AccessTokenExp time.Duration
	Request        *http.Request
}
