package server

import (
	errors2 "errors"
	"fmt"
	"github.com/GymWorkoutApp/gwap-auth/constants"
	"github.com/GymWorkoutApp/gwap-auth/errors"
	"github.com/GymWorkoutApp/gwap-auth/manager"
	"github.com/GymWorkoutApp/gwap-auth/models"
	"github.com/labstack/echo"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NewDefaultServer create a default authorization server
func NewDefaultServer(manager manager.Manager) *Server {
	return NewServer(NewConfig(), manager)
}

// NewServer create authorization server
func NewServer(cfg *Config, manager manager.Manager) *Server {
	srv := &Server{
		Config:  cfg,
		Manager: manager,
	}

	// default handlers
	srv.ClientInfoHandler = ClientFormHandler
	return srv
}

// Server Provide authorization server
type Server struct {
	Config                  *Config
	Manager                 manager.Manager
	ClientInfoHandler       ClientInfoHandler
	ClientAuthorizedHandler ClientAuthorizedHandler
	ClientScopeHandler      ClientScopeHandler
	UserInfoHandler         UserInfoHandler
	RefreshingScopeHandler  RefreshingScopeHandler
	ResponseErrorHandler    ResponseErrorHandler
	InternalErrorHandler    InternalErrorHandler
	ExtensionFieldsHandler  ExtensionFieldsHandler
	AccessTokenExpHandler   AccessTokenExpHandler
	AuthorizeScopeHandler   AuthorizeScopeHandler
}

func (s *Server) redirectError(w http.ResponseWriter, req *AuthorizeRequest, err error) (uerr error) {
	if req == nil {
		uerr = err
		return
	}
	data, _ := s.GetErrorData(err)
	err = s.redirect(w, req, data)
	return
}

func (s *Server) redirect(w http.ResponseWriter, req *AuthorizeRequest, data map[string]interface{}) (err error) {
	uri, err := s.GetRedirectURI(req, data)
	if err != nil {
		return
	}
	w.Header().Set("Location", uri)
	w.WriteHeader(302)
	return
}

func (s *Server) tokenError(err error) (map[string]interface{}, int, error) {
	data, statusCode := s.GetErrorData(err)
	return data, statusCode, nil
}

func (s *Server) token(data map[string]interface{}, statusCode ...int) (map[string]interface{}, int, error) {
	//for key := range header {
	//	w.Header().Set(key, header.Get(key))
	//}

	status := http.StatusOK
	if len(statusCode) > 0 && statusCode[0] > 0 {
		status = statusCode[0]
	}

	return data, status, nil
}

// GetRedirectURI get redirect uri
func (s *Server) GetRedirectURI(req *AuthorizeRequest, data map[string]interface{}) (uri string, err error) {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return
	}

	q := u.Query()
	if req.State != "" {
		q.Set("state", req.State)
	}

	for k, v := range data {
		q.Set(k, fmt.Sprint(v))
	}

	switch req.ResponseType {
	case constants.Code:
		u.RawQuery = q.Encode()
	case constants.Token:
		u.RawQuery = ""
		u.Fragment, err = url.QueryUnescape(q.Encode())
		if err != nil {
			return
		}
	}

	uri = u.String()
	return
}

// CheckResponseType check allows response type
func (s *Server) CheckResponseType(rt constants.ResponseType) bool {
	for _, art := range s.Config.AllowedResponseTypes {
		if art == rt {
			return true
		}
	}
	return false
}

// ValidationAuthorizeRequest the authorization request validation
func (s *Server) ValidationAuthorizeRequest(c echo.Context) (req *AuthorizeRequest, err error) {
	redirectURI, err := url.QueryUnescape(c.QueryParam("redirect_uri"))
	if err != nil {
		return
	}

	clientID := c.QueryParam("client_id")
	if clientID == "" || redirectURI == "" {
		err = errors.ErrInvalidRequest
		return
	}

	resType := constants.ResponseType(c.QueryParam("response_type"))

	if resType.String() == "" {
		err = errors.ErrUnsupportedResponseType
		return
	} else if allowed := s.CheckResponseType(resType); !allowed {
		err = errors.ErrUnauthorizedClient
		return
	}

	req = &AuthorizeRequest{
		RedirectURI:  redirectURI,
		ResponseType: resType,
		ClientID:     clientID,
		State:        c.QueryParam("state"),
		Scope:        c.QueryParam("scope"),
		Request:      c.Request(),
	}
	return
}

// GetAuthorizeToken get authorization token(code)
func (s *Server) GetAuthorizeToken(req *AuthorizeRequest, e echo.Context) (ti models.TokenInfo, err error) {
	// check the client allows the grant type
	if fn := s.ClientAuthorizedHandler; fn != nil {
		gt := constants.AuthorizationCode

		if req.ResponseType == constants.Token {
			gt = constants.Implicit
		}

		allowed, verr := fn(req.ClientID, gt)
		if verr != nil {
			err = verr
			return
		} else if !allowed {
			err = errors.ErrUnauthorizedClient
			return
		}
	}

	// check the client allows the authorized scope
	if fn := s.ClientScopeHandler; fn != nil {

		allowed, verr := fn(req.ClientID, req.Scope)
		if verr != nil {
			err = verr
			return
		} else if !allowed {
			err = errors.ErrInvalidScope
			return
		}
	}

	tgr := &manager.TokenGenerateRequest{
		ClientID:       req.ClientID,
		UserID:         req.UserID,
		RedirectURI:    req.RedirectURI,
		Scope:          req.Scope,
		AccessTokenExp: req.AccessTokenExp,
		Request:        req.Request,
	}

	ti, err = s.Manager.GenerateAuthToken(req.ResponseType, tgr, e)
	return
}

// GetAuthorizeData get authorization response data
func (s *Server) GetAuthorizeData(rt constants.ResponseType, ti models.TokenInfo) (data map[string]interface{}) {
	if rt == constants.Code {
		data = map[string]interface{}{
			"code": ti.GetCode(),
		}
	} else {
		data = s.GetTokenData(ti)
	}
	return
}

// HandleAuthorizeRequest the authorization request handling
func (s *Server) HandleAuthorizeRequest(c echo.Context) (err error) {
	req, verr := s.ValidationAuthorizeRequest(c)
	r := c.Response()
	if verr != nil {
		err = s.redirectError(r, req, verr)
		return
	}

	// user authorization
	userID, verr := s.UserAuthorizationHandler(c)

	if verr != nil {
		err = s.redirectError(r, req, verr)
		return
	} else if userID == "" {
		return
	}

	req.UserID = userID

	// specify the scope of authorization
	if fn := s.AuthorizeScopeHandler; fn != nil {

		scope, verr := fn(r, c.Request())
		if verr != nil {
			err = verr
			return
		} else if scope != "" {
			req.Scope = scope
		}
	}

	// specify the expiration time of access token
	if fn := s.AccessTokenExpHandler; fn != nil {

		exp, verr := fn(r, c.Request())
		if verr != nil {
			err = verr
			return
		}
		req.AccessTokenExp = exp
	}

	ti, verr := s.GetAuthorizeToken(req, c)
	if verr != nil {
		err = s.redirectError(r, req, verr)
		return
	}

	err = s.redirect(r, req, s.GetAuthorizeData(req.ResponseType, ti))
	return
}

// ValidationTokenRequest the token request validation
func (s *Server) ValidationTokenRequest(r *http.Request, e echo.Context) (gt constants.GrantType, tgr *manager.TokenGenerateRequest, err error) {
	if v := r.Method; v != "POST" {
		err = errors.ErrInvalidRequest
		return
	}

	gt = constants.GrantType(r.FormValue("grant_type"))

	if gt.String() == "" {
		err = errors.ErrUnsupportedGrantType
		return
	}

	clientID, clientSecret, err := s.ClientInfoHandler(r)
	if err != nil {
		return
	}

	tgr = &manager.TokenGenerateRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Request:      r,
	}

	switch gt {
	case constants.AuthorizationCode:
		tgr.RedirectURI = r.FormValue("redirect_uri")
		tgr.Code = r.FormValue("code")

		if tgr.RedirectURI == "" ||
			tgr.Code == "" {
			err = errors.ErrInvalidRequest
			return
		}
	case constants.PasswordCredentials:
		tgr.Scope = r.FormValue("scope")
		username, password := r.FormValue("username"), r.FormValue("password")

		if username == "" || password == "" {
			err = errors.ErrInvalidRequest
			return
		}

		userID, verr := s.PasswordAuthorizationHandler(username, password, e)
		if verr != nil {
			err = verr
			return
		} else if userID == "" {
			err = errors.ErrInvalidGrant
			return
		}

		tgr.UserID = userID
	case constants.ClientCredentials:
		tgr.Scope = r.FormValue("scope")
	case constants.Refreshing:
		tgr.Refresh = r.FormValue("refresh_token")
		tgr.Scope = r.FormValue("scope")

		if tgr.Refresh == "" {
			err = errors.ErrInvalidRequest
		}
	}
	return
}

// CheckGrantType check allows grant type
func (s *Server) CheckGrantType(gt constants.GrantType) bool {
	for _, agt := range s.Config.AllowedGrantTypes {
		if agt == gt {
			return true
		}
	}
	return false
}

// GetAccessToken access token
func (s *Server) GetAccessToken(gt constants.GrantType, tgr *manager.TokenGenerateRequest, e echo.Context) (ti models.TokenInfo, err error) {
	if allowed := s.CheckGrantType(gt); !allowed {
		err = errors.ErrUnauthorizedClient
		return
	}

	if fn := s.ClientAuthorizedHandler; fn != nil {
		allowed, verr := fn(tgr.ClientID, gt)
		if verr != nil {
			err = verr
			return
		} else if !allowed {
			err = errors.ErrUnauthorizedClient
			return
		}
	}

	switch gt {
	case constants.AuthorizationCode:
		ati, verr := s.Manager.GenerateAccessToken(gt, tgr, e)
		if verr != nil {

			if verr == errors.ErrInvalidAuthorizeCode {
				err = errors.ErrInvalidGrant
			} else if verr == errors.ErrInvalidClient {
				err = errors.ErrInvalidClient
			} else {
				err = verr
			}
			return
		}
		ti = ati
	case constants.PasswordCredentials, constants.ClientCredentials:
		if fn := s.ClientScopeHandler; fn != nil {

			allowed, verr := fn(tgr.ClientID, tgr.Scope)
			if verr != nil {
				err = verr
				return
			} else if !allowed {
				err = errors.ErrInvalidScope
				return
			}
		}
		ti, err = s.Manager.GenerateAccessToken(gt, tgr, e)
	case constants.Refreshing:
		// check scope
		if scope, scopeFn := tgr.Scope, s.RefreshingScopeHandler; scope != "" && scopeFn != nil {

			rti, verr := s.Manager.LoadRefreshToken(tgr.Refresh)
			if verr != nil {
				if verr == errors.ErrInvalidRefreshToken || verr == errors.ErrExpiredRefreshToken {
					err = errors.ErrInvalidGrant
					return
				}
				err = verr
				return
			}

			allowed, verr := scopeFn(scope, rti.GetScope())
			if verr != nil {
				err = verr
				return
			} else if !allowed {
				err = errors.ErrInvalidScope
				return
			}
		}

		rti, verr := s.Manager.RefreshAccessToken(tgr, e)
		if verr != nil {
			if verr == errors.ErrInvalidRefreshToken || verr == errors.ErrExpiredRefreshToken {
				err = errors.ErrInvalidGrant
			} else {
				err = verr
			}
			return
		}
		ti = rti
	}

	return
}

// GetTokenData token data
func (s *Server) GetTokenData(ti models.TokenInfo) (data map[string]interface{}) {
	data = map[string]interface{}{
		"access_token": ti.GetAccess(),
		"token_type":   s.Config.TokenType,
		"expires_in":   int64(ti.GetAccessExpiresIn() / time.Second),
	}

	if scope := ti.GetScope(); scope != "" {
		data["scope"] = scope
	}

	if refresh := ti.GetRefresh(); refresh != "" {
		data["refresh_token"] = refresh
	}

	if fn := s.ExtensionFieldsHandler; fn != nil {
		ext := fn(ti)
		for k, v := range ext {
			if _, ok := data[k]; ok {
				continue
			}
			data[k] = v
		}
	}
	return
}

// HandleTokenRequest token request handling
func (s *Server) HandleTokenRequest(c echo.Context) error {
	r := c.Request()
	gt, tgr, verr := s.ValidationTokenRequest(r, c)
	if verr != nil {
		data, status, err := s.tokenError(verr)
		if err != nil {
			return err
		}
		return c.JSON(status, data)
	}

	ti, verr := s.GetAccessToken(gt, tgr, c)
	if verr != nil {
		data, status, err := s.tokenError(verr)
		if err != nil {
			return err
		}
		return c.JSON(status, data)
	}

	data, status, err := s.token(s.GetTokenData(ti), http.StatusOK)
	if err != nil {
		return err
	}
	return c.JSON(status, data)
}

// HandleIntrospectRequest introspect request handling
func (s *Server) HandleIntrospectRequest(e echo.Context) error {
	token := string(e.QueryParam("token"))

	if token != "" {
		info, err := s.Manager.LoadAccessToken(token)

		if err != nil {
			data, status, err := s.tokenError( err)
			if err != nil {
				return err
			}
			return e.JSON(status, data)
		}

		data, status, err := s.token(s.GetTokenData(info), http.StatusOK)
		if err != nil {
			return err
		}
		return e.JSON(status, data)
	} else {
		e.Error(errors.NewResponse(errors2.New("Token is required"), http.StatusBadRequest, ""))
		return nil
	}
}

// HandleClientCreateRequest introspect request handling
func (s *Server) HandleClientCreateRequest(e echo.Context) (error) {
	client := new(models.Client)
	if err := e.Bind(client); err != nil {
		return err
	}
	clientSave, err := s.Manager.CreateClient(client, e)
	if err != nil {
		return err
	}
	return e.JSON(http.StatusCreated, clientSave)
}

// HandleClientUpdateRequest introspect request handling
func (s *Server) HandleClientUpdateRequest(e echo.Context) (err error) {
	client := new(models.Client)
	if err := e.Bind(client); err != nil {
		return err
	}
	clientSave, err := s.Manager.UpdateClient(client, e)
	if err != nil {
		return err
	}
	return e.JSON(http.StatusOK, clientSave)
}

// HandleClientGetRequest introspect request handling
func (s *Server) HandleClientGetRequest(e echo.Context) (err error) {
	client := new(models.Client)
	if err := e.Bind(client); err != nil {
		return err
	}
	id := e.Param("id")
	if id != "" {
		clientSave, err := s.Manager.GetClientById(id, e)
		if err != nil {
			return err
		}
		return e.JSON(http.StatusOK, clientSave)
	} else {
		clientSave, err := s.Manager.GetClient(client, e)
		if err != nil {
			return err
		}
		return e.JSON(http.StatusOK, clientSave)
	}
}

// HandleUserCreateUpdateRequest introspect request handling
func (s *Server) HandleUserCreateRequest(e echo.Context) error {
	user := new(models.User)
	if err := e.Bind(user); err != nil {
		return err
	}
	if err := e.Validate(user); err != nil {
		return errors.NewResponseByError(err)
	}

	userSave, err := s.Manager.CreateUser(user, e)
	if err != nil {
		return err
	}
	return e.JSON(http.StatusCreated, userSave)
}

// HandleUserCreateUpdateRequest introspect request handling
func (s *Server) HandleUserUpdateRequest(e echo.Context) error {
	token := string(e.QueryParam("token"))

	if token != "" {
		info, err := s.Manager.LoadAccessToken(token)

		if err != nil {
			data, status, err := s.tokenError(err)
			if err != nil {
				return nil
			}
			return e.JSON(status, data)
		}

		data, status, err := s.token(s.GetTokenData(info), http.StatusOK)
		if err != nil {
			return nil
		}
		return e.JSON(status, data)
	} else {
		e.Error(errors.NewResponse(errors2.New("Token is required"), http.StatusBadRequest, ""))
		return nil
	}
}

// HandleUserGetRequest introspect request handling
func (s *Server) HandleUserGetRequest(e echo.Context) (error) {
	return nil
}

// HandleHealthCheckGetRequest introspect request handling
func (s *Server) HandleHealthCheckGetRequest(e echo.Context) error {
	return e.JSON(http.StatusOK, map[string]string{"status": "Healthy"})
}

// GetErrorData get error response data
func (s *Server) GetErrorData(err error) (data map[string]interface{}, statusCode int) {
	re := new(echo.HTTPError)

	if v, ok := errors.Descriptions[err]; ok {
		re.Internal = err
		re.Message = v
		re.Code = errors.StatusCodes[err]
	} else {
		if fn := s.InternalErrorHandler; fn != nil {
			if vre := fn(err); vre != nil {
				re = vre
			}
		}

		if re.Internal == nil {
			re.Internal = errors.ErrServerError
			re.Message = errors.Descriptions[errors.ErrServerError]
			re.Code = errors.StatusCodes[errors.ErrServerError]
		}
	}

	if fn := s.ResponseErrorHandler; fn != nil {
		fn(re)

		if re == nil {
			re = new(echo.HTTPError)
		}
	}

	data = make(map[string]interface{})

	if err := re.Internal; err != nil {
		data["error"] = err.Error()
	}

	if v := re.Code; v != 0 {
		data["error_code"] = v
	}

	if v := re.Message; v != "" {
		data["error_description"] = v
	}

	statusCode = http.StatusInternalServerError
	if v := re.Code; v > 0 {
		statusCode = v
	}

	return
}

// BearerAuth parse bearer token
func (s *Server) BearerAuth(r *http.Request) (accessToken string, ok bool) {
	auth := r.Header.Get("Authorization")
	prefix := "Bearer "

	if auth != "" && strings.HasPrefix(auth, prefix) {
		accessToken = auth[len(prefix):]
	} else {
		accessToken = r.FormValue("access_token")
	}

	if accessToken != "" {
		ok = true
	}

	return
}

// ValidationBearerToken validation the bearer tokens
// https://tools.ietf.org/html/rfc6750
func (s *Server) ValidationBearerToken(r *http.Request) (ti models.TokenInfo, err error) {
	accessToken, ok := s.BearerAuth(r)
	if !ok {
		err = errors.ErrInvalidAccessToken
		return
	}

	ti, err = s.Manager.LoadAccessToken(accessToken)

	return
}

// ValidationBearerToken validation the bearer tokens
// https://tools.ietf.org/html/rfc6750
func (s *Server) MiddlewareAuthClient(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		accessToken, ok := s.BearerAuth(c.Request())
		if !ok {
			return errors.ErrInvalidAccessToken
		}
		ti, err := s.Manager.LoadAccessToken(accessToken)
		if err != nil {
			data, status, err := s.tokenError(err)
			if err != nil {
				return nil
			}
			c.JSON(status, data)
		}

		c.Set("UserID", ti.GetUserID())
		c.Set("ClientID", ti.GetClientID())
		return next(c)
	}
}

func (s *Server) UserAuthorizationHandler(e echo.Context) (userID string, err error) {
	username := e.QueryParam("username")
	if username == "" {
		err = errors.ErrAccessDenied
	}

	s.Manager.GetUser(&models.User{Username: username}, e)
	return
}

func (s *Server) PasswordAuthorizationHandler(username string, password string, e echo.Context) (userID string, err error) {
	users, err := s.Manager.GetUser(models.User{Username: username, Password: password}, e)
	if err != nil {
		return
	}
	if len(users) == 1 {
		userID = users[0].GetID()
	} else {
		err = errors.ErrAccessDenied
	}
	return
}
