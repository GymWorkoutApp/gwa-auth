package store

import (
	"github.com/GymWorkoutApp/gwap-auth/models"
	"github.com/labstack/echo"
)

type (
	// ClientStore the client information storage interface
	ClientStore interface {
		// according to the ID for the client information
		GetByID(id string, e echo.Context) (models.ClientInfo, error)
		Get(cli models.ClientInfo, e echo.Context) ([]models.ClientInfo, error)
		Create(cli models.ClientInfo, e echo.Context) (models.ClientInfo, error)
		Update(cli models.ClientInfo, e echo.Context) (models.ClientInfo, error)
		RemoveByID(id string,  e echo.Context) (error)
	}

	// ClientStore the client information storage interface
	UserStore interface {
		// according to the ID for the client information
		GetByID(id string, e echo.Context) (models.UserInfo, error)
		GetByUsername(username string, e echo.Context) (models.UserInfo, error)
		Get(user models.UserInfo, e echo.Context) ([]models.UserInfo, error)
		Create(user models.UserInfo, e echo.Context) (models.UserInfo, error)
		Update(user models.UserInfo, e echo.Context) (models.UserInfo, error)
		RemoveByID(id string, e echo.Context) (error)
	}

	// TokenStore the token information storage interface
	TokenStore interface {
		// create and store the new token information
		Create(info models.TokenInfo) error

		// delete the authorization code
		RemoveByCode(code string) error

		// use the access token to delete the token information
		RemoveByAccess(access string) error

		// use the refresh token to delete the token information
		RemoveByRefresh(refresh string) error

		// use the authorization code for token information data
		GetByCode(code string) (models.TokenInfo, error)

		// use the access token for token information data
		GetByAccess(access string) (models.TokenInfo, error)

		// use the refresh token for token information data
		GetByRefresh(refresh string) (models.TokenInfo, error)
	}
)
