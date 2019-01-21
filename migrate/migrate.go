package main

import (
	"context"
	"github.com/GymWorkoutApp/gwap-auth/database"
	"github.com/GymWorkoutApp/gwap-auth/models"
)

func main() {
	db := database.NewManageDB().Get(context.TODO())
	defer db.Close()
	db.AutoMigrate(&models.Client{}, &models.User{})
}
