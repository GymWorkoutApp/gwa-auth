package models

import (
	"github.com/GymWorkoutApp/gwap-auth/utils/uuid"
	"github.com/jinzhu/gorm"
)

// Client client model
type Client struct {
	Base

	ID     		string `json:"id" gorm:"not null;primary_key;"`
	Secret 		string `json:"secret" gorm:"not null;"`
	Domain 		string `json:"domain"`
	UserID 		string `json:"user_id" gorm:"not null;"`
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