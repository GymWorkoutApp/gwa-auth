package models

import "time"

type Base struct {
	CreatedAt time.Time  `json:"created_at" gorm:"not null;"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"-" sql:"index"`
}
