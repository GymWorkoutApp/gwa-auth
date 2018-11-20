package manager

import (
	"github.com/GymWorkoutApp/gwa_auth/constants"
	"github.com/GymWorkoutApp/gwa_auth/models"
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
	GetClientById(clientID string) (cli models.ClientInfo, err error)

	// get the client information
	GetClient(cli models.ClientInfo) ([]models.ClientInfo, error)

	// create the client information
	CreateClient(cli models.ClientInfo) (models.ClientInfo, error)

	// update the client information
	UpdateClient(cli models.ClientInfo) (models.ClientInfo, error)

	// get the client information
	GetUser(userID string) (cli models.UserInfo, err error)

	// create the client information
	CreateUser(user models.UserInfo) (models.UserInfo, error)

	// update the client information
	UpdateUser(user models.UserInfo) (models.UserInfo, error)

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
