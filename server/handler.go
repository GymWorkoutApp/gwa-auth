package server

import (
	"github.com/GymWorkoutApp/gwap-auth/constants"
	"github.com/GymWorkoutApp/gwap-auth/errors"
	"github.com/GymWorkoutApp/gwap-auth/models"
	"net/http"
	"time"
)

type (
	// ClientInfoHandler get client info from request
	ClientInfoHandler func(r *http.Request) (clientID, clientSecret string, err error)

	// ClientAuthorizedHandler check the client allows to use this authorization grant type
	ClientAuthorizedHandler func(clientID string, grant constants.GrantType) (allowed bool, err error)

	// ClientScopeHandler check the client allows to use" scope
	ClientScopeHandler func(clientID, scope string) (allowed bool, err error)

	// UserInfoHandler get user info from request
	UserInfoHandler func(r *http.Request) (username string, password string, err error)

	// UserAuthorizationHandler get user id from request authorization
	UserAuthorizationHandler func(w http.ResponseWriter, r *http.Request) (userID string, err error)

	// PasswordAuthorizationHandler get user id from username and password
	PasswordAuthorizationHandler func(username, password string) (userID string, err error)

	// RefreshingScopeHandler check the scope of the refreshing token
	RefreshingScopeHandler func(newScope, oldScope string) (allowed bool, err error)

	// ResponseErrorHandler response error handing
	ResponseErrorHandler func(re *errors.Response)

	// InternalErrorHandler internal error handing
	InternalErrorHandler func(err error) (re *errors.Response)

	// AuthorizeScopeHandler set the authorized scope
	AuthorizeScopeHandler func(w http.ResponseWriter, r *http.Request) (scope string, err error)

	// AccessTokenExpHandler set expiration date for the access token
	AccessTokenExpHandler func(w http.ResponseWriter, r *http.Request) (exp time.Duration, err error)

	// ExtensionFieldsHandler in response to the access token with the extension of the field
	ExtensionFieldsHandler func(ti models.TokenInfo) (fieldsValue map[string]interface{})
)

// ClientFormHandler get client data from form
func ClientFormHandler(r *http.Request) (clientID, clientSecret string, err error) {
	clientID = r.Form.Get("client_id")
	clientSecret = r.Form.Get("client_secret")
	if clientID == "" || clientSecret == "" {
		err = errors.ErrInvalidClient
	}
	return
}

// ClientBasicHandler get client data from basic authorization
func ClientBasicHandler(r *http.Request) (clientID, clientSecret string, err error) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		err = errors.ErrInvalidClient
		return
	}
	return
}

