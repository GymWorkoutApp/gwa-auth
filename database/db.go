package database

import (
	"context"
	"fmt"
	"github.com/jinzhu/gorm"
	"go.elastic.co/apm/module/apmgorm"
	_ "go.elastic.co/apm/module/apmgorm/dialects/postgres"
	"os"
)

func NewManageDB() *ManageDB {
	return &ManageDB{}
}

type ManageDB struct {

}

func (cs *ManageDB) Get(con context.Context) *gorm.DB {
	config := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"), os.Getenv("DB_SSLMODE"))
	db, err := apmgorm.Open("postgres", config)
	db = apmgorm.WithContext(con, db)
	if err != nil {
		panic(err)
	}

	return db
}



