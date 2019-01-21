package manager

import (
	"github.com/GymWorkoutApp/gwap-auth/constants"
	"github.com/GymWorkoutApp/gwap-auth/models"
	"github.com/labstack/echo"
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
	GetClientById(clientID string, e echo.Context) (cli models.ClientInfo, err error)

	// get the client information
	GetClient(cli models.ClientInfo, e echo.Context) ([]models.ClientInfo, error)

	// create the client information
	CreateClient(cli models.ClientInfo, e echo.Context) (models.ClientInfo, error)

	// update the client information
	UpdateClient(cli models.ClientInfo, e echo.Context) (models.ClientInfo, error)

	// get the user information
	GetUserByID(userID string, e echo.Context) (models.UserInfo, error)

	// get the user information
	GetUser(user models.UserInfo, e echo.Context) ([]models.UserInfo, error)

	// get the user information
	GetUserByUsername(username string, e echo.Context) (models.UserInfo, error)

	// create the client information
	CreateUser(user models.UserInfo, e echo.Context) (models.UserInfo, error)

	// update the client information
	UpdateUser(user models.UserInfo, e echo.Context) (models.UserInfo, error)

	// generate the authorization token(code)
	GenerateAuthToken(rt constants.ResponseType, tgr *TokenGenerateRequest, e echo.Context) (authToken models.TokenInfo, err error)

	// generate the access token
	GenerateAccessToken(rt constants.GrantType, tgr *TokenGenerateRequest, e echo.Context) (accessToken models.TokenInfo, err error)

	// refreshing an access token
	RefreshAccessToken(tgr *TokenGenerateRequest, e echo.Context) (accessToken models.TokenInfo, err error)

	// use the access token to delete the token information
	RemoveAccessToken(access string) (err error)

	// use the refresh token to delete the token information
	RemoveRefreshToken(refresh string) (err error)

	// according to the access token for corresponding token information
	LoadAccessToken(access string) (ti models.TokenInfo, err error)

	// according to the refresh token for corresponding token information
	LoadRefreshToken(refresh string) (ti models.TokenInfo, err error)
}
