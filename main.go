package main

import (
	"fmt"
	"github.com/GymWorkoutApp/gwa_auth/database"
	"github.com/GymWorkoutApp/gwa_auth/models"
	"github.com/GymWorkoutApp/gwa_auth/store"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/middleware"
	echolog "github.com/labstack/gommon/log"
	"log"
	"os"

	"github.com/GymWorkoutApp/gwa_auth/errors"
	"github.com/GymWorkoutApp/gwa_auth/generates"
	"github.com/GymWorkoutApp/gwa_auth/manager"
	"github.com/GymWorkoutApp/gwa_auth/server"
	"github.com/labstack/echo"
)

func main() {

	managerServer := manager.NewDefaultManager()
	managerServer.MapAccessGenerate(generates.NewJWTAccessGenerate([]byte("00000000"), jwt.SigningMethodHS512))

	// token memory store
	managerServer.MapTokenStorage(store.NewRedisStore())

	srv := server.NewDefaultServer(managerServer)

	db := database.NewManageDB().Get()
	defer db.Close()
	db.AutoMigrate(&models.Client{}, &models.User{})

	// client store
	managerServer.MapClientStorage(store.NewClientStore())

	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		re = &errors.Response{Error: err, StatusCode: 500, Description: err.Error()}
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	// Http handlers

	e := echo.New()
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "${time_rfc3339_nano} - [${uri} - ${method}] - ${status} - ${remote_ip}\n",
	}))

	oauth2 := e.Group("oauth2")

	oauth2.GET("/authorize", srv.HandleAuthorizeRequest)
	oauth2.POST("/token", srv.HandleTokenRequest)
	oauth2.GET("/introspect", srv.HandleIntrospectRequest)

	auth := e.Group("auth")
	auth.Use(srv.MiddlewareAuthClient)
	auth.POST("/users", srv.HandleUserCreateRequest)
	auth.PUT("/users/:id", srv.HandleUserUpdateRequest)
	auth.PATCH("/users/:id", srv.HandleUserUpdateRequest)
	auth.GET("/users", srv.HandleUserGetRequest)

	auth.POST("/clients", srv.HandleClientCreateRequest)
	auth.PUT("/clients/:id", srv.HandleClientUpdateRequest)
	auth.PATCH("/clients/:id", srv.HandleClientUpdateRequest)
	auth.GET("/clients", srv.HandleClientGetRequest)
	auth.GET("/clients/:id", srv.HandleClientGetRequest)

	e.Logger.SetLevel(echolog.INFO)
	e.Logger.Fatal(e.Start(fmt.Sprintf(":%v",os.Getenv("PORT"))))
}