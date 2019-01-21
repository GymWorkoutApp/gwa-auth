package generates

import (
	"github.com/GymWorkoutApp/gwap-auth/models"
	"net/http"
	"time"
)

type (
	// GenerateBasic provide the basis of the generated token data
	GenerateBasic struct {
		Client    models.ClientInfo
		UserID    string
		CreateAt  time.Time
		TokenInfo models.TokenInfo
		Request   *http.Request
	}

	AccessGenerate interface {
		Token(data *GenerateBasic, isGenRefresh bool) (access, refresh string, err error)
	}
)
