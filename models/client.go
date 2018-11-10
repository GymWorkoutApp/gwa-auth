package models

import (
	"github.com/GymWorkoutApp/gwa_auth/utils/uuid"
	"github.com/jinzhu/gorm"
	"time"
)

// Client client model
type Client struct {
	//gorm.Model

	ID     		string `json:"id" gorm:"not null;primary_key;"`
	Secret 		string
	Domain 		string
	UserID 		string
	CreatedAt 	time.Time
	UpdatedAt 	time.Time
	DeletedAt 	*time.Time `sql:"index"`
}

// GetID client id
func (c Client) GetID() string {
	return c.ID
}

// SetID client id
func (c Client) SetID(id string) {
	c.ID = id
}

// GetSecret client domain
func (c Client) GetSecret() string {
	return c.Secret
}

// GetDomain client domain
func (c Client) GetDomain() string {
	return c.Domain
}

// GetUserID user id
func (c Client) GetUserID() string {
	return c.UserID
}

func (c *Client) BeforeCreate(scope *gorm.Scope) error {
	scope.SetColumn("ID", uuid.Must(uuid.NewRandom()).String())
	return nil
}