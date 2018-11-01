package manager

import (
	"github.com/GymWorkoutApp/gwa_auth.server/constants"
	"github.com/GymWorkoutApp/gwa_auth.server/models"
	"net/http"
	"time"
)

// TokenGenerateRequest provide to generate the token request parameters
type TokenGenerateRequest struct {
	ClientID       string
	ClientSecret   string
	UserID         string
	RedirectURI    string
	Scope          string
	Code           string
	Refresh        string
	AccessTokenExp time.Duration
	Request        *http.Request
}

// Manager authorization management interface
type Manager interface {
	// get the client information
	GetClient(clientID string) (cli models.ClientInfo, err error)

	// generate the authorization token(code)
	GenerateAuthToken(rt constants.ResponseType, tgr *TokenGenerateRequest) (authToken models.TokenInfo, err error)

	// generate the access token
	GenerateAccessToken(rt constants.GrantType, tgr *TokenGenerateRequest) (accessToken models.TokenInfo, err error)

	// refreshing an access token
	RefreshAccessToken(tgr *TokenGenerateRequest) (accessToken models.TokenInfo, err error)

	// use the access token to delete the token information
	RemoveAccessToken(access string) (err error)

	// use the refresh token to delete the token information
	RemoveRefreshToken(refresh string) (err error)

	// according to the access token for corresponding token information
	LoadAccessToken(access string) (ti models.TokenInfo, err error)

	// according to the refresh token for corresponding token information
	LoadRefreshToken(refresh string) (ti models.TokenInfo, err error)
}
