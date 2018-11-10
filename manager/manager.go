package manager

import (
	"github.com/GymWorkoutApp/gwa_auth/constants"
	"github.com/GymWorkoutApp/gwa_auth/errors"
	"github.com/GymWorkoutApp/gwa_auth/generates"
	"github.com/GymWorkoutApp/gwa_auth/models"
	"github.com/GymWorkoutApp/gwa_auth/store"
	"time"
)

// NewDefaultManager create to default authorization management instance
func NewDefaultManager() (m *ManagerStandard) {
	m = NewManagerStandard()
	// default implementation
	m.MapAuthorizeGenerate(*generates.NewAuthorizeGenerate())
	m.MapAccessGenerate(generates.NewAccessGenerate())
	return
}

// NewManager create to authorization management instance
func NewManagerStandard() *ManagerStandard {
	return &ManagerStandard{
		gtcfg:       make(map[constants.GrantType]*Config),
		validateURI: DefaultValidateURI,
	}
}

// Manager provide authorization management
type ManagerStandard struct {
	codeExp           time.Duration
	gtcfg             map[constants.GrantType]*Config
	rcfg              *RefreshingConfig
	validateURI       ValidateURIHandler
	authorizeGenerate generates.AuthorizeGenerate
	accessGenerate    generates.AccessGenerate
	tokenStore        store.TokenStore
	clientStore       store.ClientStore
}

// get grant type config
func (m *ManagerStandard) grantConfig(gt constants.GrantType) *Config {
	if c, ok := m.gtcfg[gt]; ok && c != nil {
		return c
	}
	switch gt {
	case constants.AuthorizationCode:
		return DefaultAuthorizeCodeTokenCfg
	case constants.Implicit:
		return DefaultImplicitTokenCfg
	case constants.PasswordCredentials:
		return DefaultPasswordTokenCfg
	case constants.ClientCredentials:
		return DefaultClientTokenCfg
	}
	return &Config{}
}

// SetAuthorizeCodeExp set the authorization code expiration time
func (m *ManagerStandard) SetAuthorizeCodeExp(exp time.Duration) {
	m.codeExp = exp
}

// SetAuthorizeCodeTokenCfg set the authorization code grant token config
func (m *ManagerStandard) SetAuthorizeCodeTokenCfg(cfg *Config) {
	m.gtcfg[constants.AuthorizationCode] = cfg
}

// SetImplicitTokenCfg set the implicit grant token config
func (m *ManagerStandard) SetImplicitTokenCfg(cfg *Config) {
	m.gtcfg[constants.Implicit] = cfg
}

// SetPasswordTokenCfg set the password grant token config
func (m *ManagerStandard) SetPasswordTokenCfg(cfg *Config) {
	m.gtcfg[constants.PasswordCredentials] = cfg
}

// SetClientTokenCfg set the client grant token config
func (m *ManagerStandard) SetClientTokenCfg(cfg *Config) {
	m.gtcfg[constants.ClientCredentials] = cfg
}

// SetRefreshTokenCfg set the refreshing token config
func (m *ManagerStandard) SetRefreshTokenCfg(cfg *RefreshingConfig) {
	m.rcfg = cfg
}

// SetValidateURIHandler set the validates that RedirectURI is contained in baseURI
func (m *ManagerStandard) SetValidateURIHandler(handler ValidateURIHandler) {
	m.validateURI = handler
}

// MapAuthorizeGenerate mapping the authorize code generate interface
func (m *ManagerStandard) MapAuthorizeGenerate(gen generates.AuthorizeGenerate) {
	m.authorizeGenerate = gen
}

// MapAccessGenerate mapping the access token generate interface
func (m *ManagerStandard) MapAccessGenerate(gen generates.AccessGenerate) {
	m.accessGenerate = gen
}

// MapClientStorage mapping the client store interface
func (m *ManagerStandard) MapClientStorage(stor store.ClientStore) {
	m.clientStore = stor
}

// MustClientStorage mandatory mapping the client store interface
func (m *ManagerStandard) MustClientStorage(stor store.ClientStore, err error) {
	if err != nil {
		panic(err.Error())
	}
	m.clientStore = stor
}

// MapTokenStorage mapping the token store interface
func (m *ManagerStandard) MapTokenStorage(stor store.TokenStore) {
	m.tokenStore = stor
}

// MustTokenStorage mandatory mapping the token store interface
func (m *ManagerStandard) MustTokenStorage(stor store.TokenStore, err error) {
	if err != nil {
		panic(err)
	}
	m.tokenStore = stor
}

// GetClient get the client information
func (m *ManagerStandard) GetClient(clientID string) (cli models.ClientInfo, err error) {
	cli, err = m.clientStore.GetByID(clientID)
	if err != nil {
		return
	} else if cli == nil {
		err = errors.ErrInvalidClient
	}
	return
}

// GenerateAuthToken generate the authorization token(code)
func (m *ManagerStandard) GenerateAuthToken(rt constants.ResponseType, tgr *TokenGenerateRequest) (authToken models.TokenInfo, err error) {
	cli, err := m.GetClient(tgr.ClientID)
	if err != nil {
		return
	} else if verr := m.validateURI(cli.GetDomain(), tgr.RedirectURI); verr != nil {
		err = verr
		return
	}

	ti := models.NewToken()
	ti.SetClientID(tgr.ClientID)
	ti.SetUserID(tgr.UserID)
	ti.SetRedirectURI(tgr.RedirectURI)
	ti.SetScope(tgr.Scope)

	createAt := time.Now()
	td := &generates.GenerateBasic{
		Client:    cli,
		UserID:    tgr.UserID,
		CreateAt:  createAt,
		TokenInfo: ti,
		Request:   tgr.Request,
	}
	switch rt {
	case constants.Code:
		codeExp := m.codeExp
		if codeExp == 0 {
			codeExp = DefaultCodeExp
		}
		ti.SetCodeCreateAt(createAt)
		ti.SetCodeExpiresIn(codeExp)
		if exp := tgr.AccessTokenExp; exp > 0 {
			ti.SetAccessExpiresIn(exp)
		}

		tv, terr := m.authorizeGenerate.Token(td)
		if terr != nil {
			err = terr
			return
		}
		ti.SetCode(tv)
	case constants.Token:
		// set access token expires
		icfg := m.grantConfig(constants.Implicit)
		aexp := icfg.AccessTokenExp
		if exp := tgr.AccessTokenExp; exp > 0 {
			aexp = exp
		}
		ti.SetAccessCreateAt(createAt)
		ti.SetAccessExpiresIn(aexp)

		if icfg.IsGenerateRefresh {
			ti.SetRefreshCreateAt(createAt)
			ti.SetRefreshExpiresIn(icfg.RefreshTokenExp)
		}

		tv, rv, terr := m.accessGenerate.Token(td, icfg.IsGenerateRefresh)
		if terr != nil {
			err = terr
			return
		}
		ti.SetAccess(tv)

		if rv != "" {
			ti.SetRefresh(rv)
		}
	}

	err = m.tokenStore.Create(ti)
	if err != nil {
		return
	}
	authToken = ti
	return
}

// get authorization code data
func (m *ManagerStandard) getAuthorizationCode(code string) (info models.TokenInfo, err error) {
	ti, terr := m.tokenStore.GetByCode(code)
	if terr != nil {
		err = terr
		return
	} else if ti == nil || ti.GetCode() != code || ti.GetCodeCreateAt().Add(ti.GetCodeExpiresIn()).Before(time.Now()) {
		err = errors.ErrInvalidAuthorizeCode
		return
	}
	info = ti
	return
}

// delete authorization code data
func (m *ManagerStandard) delAuthorizationCode(code string) (err error) {
	err = m.tokenStore.RemoveByCode(code)
	return
}

// GenerateAccessToken generate the access token
func (m *ManagerStandard) GenerateAccessToken(gt constants.GrantType, tgr *TokenGenerateRequest) (accessToken models.TokenInfo, err error) {
	if gt == constants.AuthorizationCode {
		ti, terr := m.getAuthorizationCode(tgr.Code)
		if terr != nil {
			err = terr
			return
		} else if ti.GetRedirectURI() != tgr.RedirectURI || ti.GetClientID() != tgr.ClientID {
			err = errors.ErrInvalidAuthorizeCode
			return
		} else if verr := m.delAuthorizationCode(tgr.Code); verr != nil {
			err = verr
			return
		}
		tgr.UserID = ti.GetUserID()
		tgr.Scope = ti.GetScope()
		if exp := ti.GetAccessExpiresIn(); exp > 0 {
			tgr.AccessTokenExp = exp
		}
	}

	cli, err := m.GetClient(tgr.ClientID)
	if err != nil {
		return
	} else if tgr.ClientSecret != cli.GetSecret() {
		err = errors.ErrInvalidClient
		return
	}

	ti := models.NewToken()
	ti.SetClientID(tgr.ClientID)
	ti.SetUserID(tgr.UserID)
	ti.SetRedirectURI(tgr.RedirectURI)
	ti.SetScope(tgr.Scope)

	createAt := time.Now()
	ti.SetAccessCreateAt(createAt)

	// set access token expires
	gcfg := m.grantConfig(gt)
	aexp := gcfg.AccessTokenExp
	if exp := tgr.AccessTokenExp; exp > 0 {
		aexp = exp
	}
	ti.SetAccessExpiresIn(aexp)
	if gcfg.IsGenerateRefresh {
		ti.SetRefreshCreateAt(createAt)
		ti.SetRefreshExpiresIn(gcfg.RefreshTokenExp)
	}

	td := &generates.GenerateBasic{
		Client:    cli,
		UserID:    tgr.UserID,
		CreateAt:  createAt,
		TokenInfo: ti,
		Request:   tgr.Request,
	}

	av, rv, terr := m.accessGenerate.Token(td, gcfg.IsGenerateRefresh)
	if terr != nil {
		err = terr
		return
	}
	ti.SetAccess(av)

	if rv != "" {
		ti.SetRefresh(rv)
	}

	err = m.tokenStore.Create(ti)
	if err != nil {
		return
	}
	accessToken = ti

	return
}

// RefreshAccessToken refreshing an access token
func (m *ManagerStandard) RefreshAccessToken(tgr *TokenGenerateRequest) (accessToken models.TokenInfo, err error) {
	cli, err := m.GetClient(tgr.ClientID)
	if err != nil {
		return
	} else if tgr.ClientSecret != cli.GetSecret() {
		err = errors.ErrInvalidClient
		return
	}

	ti, err := m.LoadRefreshToken(tgr.Refresh)
	if err != nil {
		return
	} else if ti.GetClientID() != tgr.ClientID {
		err = errors.ErrInvalidRefreshToken
		return
	}

	oldAccess, oldRefresh := ti.GetAccess(), ti.GetRefresh()

	td := &generates.GenerateBasic{
		Client:    cli,
		UserID:    ti.GetUserID(),
		CreateAt:  time.Now(),
		TokenInfo: ti,
		Request:   tgr.Request,
	}

	rcfg := DefaultRefreshTokenCfg
	if v := m.rcfg; v != nil {
		rcfg = v
	}

	ti.SetAccessCreateAt(td.CreateAt)
	if v := rcfg.AccessTokenExp; v > 0 {
		ti.SetAccessExpiresIn(v)
	}

	if v := rcfg.RefreshTokenExp; v > 0 {
		ti.SetRefreshExpiresIn(v)
	}

	if rcfg.IsResetRefreshTime {
		ti.SetRefreshCreateAt(td.CreateAt)
	}

	if scope := tgr.Scope; scope != "" {
		ti.SetScope(scope)
	}

	tv, rv, terr := m.accessGenerate.Token(td, rcfg.IsGenerateRefresh)
	if terr != nil {
		err = terr
		return
	}

	ti.SetAccess(tv)
	if rv != "" {
		ti.SetRefresh(rv)
	}

	if verr := m.tokenStore.Create(ti); verr != nil {
		err = verr
		return
	}

	if rcfg.IsRemoveAccess {
		// remove the old access token
		if verr := m.tokenStore.RemoveByAccess(oldAccess); verr != nil {
			err = verr
			return
		}
	}

	if rcfg.IsRemoveRefreshing && rv != "" {
		// remove the old refresh token
		if verr := m.tokenStore.RemoveByRefresh(oldRefresh); verr != nil {
			err = verr
			return
		}
	}

	accessToken = ti
	if rv == "" {
		accessToken.SetRefresh("")
		accessToken.SetRefreshCreateAt(time.Now())
		accessToken.SetRefreshExpiresIn(0)
	}

	return
}

// RemoveAccessToken use the access token to delete the token information
func (m *ManagerStandard) RemoveAccessToken(access string) (err error) {
	if access == "" {
		err = errors.ErrInvalidAccessToken
		return
	}
	err = m.tokenStore.RemoveByAccess(access)
	return
}

// RemoveRefreshToken use the refresh token to delete the token information
func (m *ManagerStandard) RemoveRefreshToken(refresh string) (err error) {
	if refresh == "" {
		err = errors.ErrInvalidAccessToken
		return
	}
	err = m.tokenStore.RemoveByRefresh(refresh)
	return
}

// LoadAccessToken according to the access token for corresponding token information
func (m *ManagerStandard) LoadAccessToken(access string) (info models.TokenInfo, err error) {
	if access == "" {
		err = errors.ErrInvalidAccessToken
		return
	}

	ct := time.Now()
	ti, terr := m.tokenStore.GetByAccess(access)
	if terr != nil {
		err = terr
		return
	} else if ti == nil || ti.GetAccess() != access {
		err = errors.ErrInvalidAccessToken
		return
	} else if ti.GetRefresh() != "" && ti.GetRefreshCreateAt().Add(ti.GetRefreshExpiresIn()).Before(ct) {
		err = errors.ErrExpiredRefreshToken
		return
	} else if ti.GetAccessCreateAt().Add(ti.GetAccessExpiresIn()).Before(ct) {
		err = errors.ErrExpiredAccessToken
		return
	}
	info = ti
	return
}

// LoadRefreshToken according to the refresh token for corresponding token information
func (m *ManagerStandard) LoadRefreshToken(refresh string) (info models.TokenInfo, err error) {
	if refresh == "" {
		err = errors.ErrInvalidRefreshToken
		return
	}

	ti, terr := m.tokenStore.GetByRefresh(refresh)
	if terr != nil {
		err = terr
		return
	} else if ti == nil || ti.GetRefresh() != refresh {
		err = errors.ErrInvalidRefreshToken
		return
	} else if ti.GetRefreshCreateAt().Add(ti.GetRefreshExpiresIn()).Before(time.Now()) {
		err = errors.ErrExpiredRefreshToken
		return
	}
	info = ti
	return
}
