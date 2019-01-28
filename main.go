package main

import (
	"fmt"
	"github.com/GymWorkoutApp/gwap-auth/generates"
	"github.com/GymWorkoutApp/gwap-auth/manager"
	"github.com/GymWorkoutApp/gwap-auth/server"
	"github.com/GymWorkoutApp/gwap-auth/store"
	validator2 "github.com/GymWorkoutApp/gwap-auth/validator"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	echolog "github.com/labstack/gommon/log"
	"go.elastic.co/apm/module/apmecho"
	"log"
	"os"
)

func main() {

	managerServer := manager.NewDefaultManager()
	managerServer.MapAccessGenerate(generates.NewJWTAccessGenerate([]byte(os.Getenv("TOKEN_KEY")), jwt.SigningMethodHS512))

	// token memory store
	managerServer.MapTokenStorage(store.NewRedisStore())
	managerServer.MapClientStorage(store.NewClientStore())
	managerServer.MapUserStorage(store.NewUserStore())

	srv := server.NewDefaultServer(managerServer)

	srv.SetInternalErrorHandler(func(err error) (re *echo.HTTPError) {
		log.Println("Internal Error:", err.Error())
		re = &echo.HTTPError{Internal: err, Code: 500, Message: err.Error()}
		return
	})

	srv.SetResponseErrorHandler(func(re *echo.HTTPError) {
		log.Println("Response Error:", re.Internal.Error())
	})

	// Http handlers

	e := echo.New()
	e.Use(apmecho.Middleware())
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "${time_rfc3339_nano} - [${uri} - ${method}] - ${status} - [${remote_ip}]\n",
	}))
	e.Validator = validator2.NewValidator()

	gwap := e.Group("/gwap/auth")
	gwap.GET("/", srv.HandleHealthCheckGetRequest)

	oauth2 := gwap.Group("/oauth2")

	oauth2.GET("/authorize", srv.HandleAuthorizeRequest)
	oauth2.POST("/token", srv.HandleTokenRequest)
	oauth2.GET("/introspect", srv.HandleIntrospectRequest)

	v1 := gwap.Group("/v1")
	v1.Use(srv.MiddlewareAuthClient)
	v1.POST("/users", srv.HandleUserCreateRequest)
	v1.PUT("/users/:id", srv.HandleUserUpdateRequest)
	v1.PATCH("/users/:id", srv.HandleUserUpdateRequest)
	v1.GET("/users", srv.HandleUserGetRequest)

	v1.POST("/clients", srv.HandleClientCreateRequest)
	v1.PUT("/clients/:id", srv.HandleClientUpdateRequest)
	v1.PATCH("/clients/:id", srv.HandleClientUpdateRequest)
	v1.GET("/clients", srv.HandleClientGetRequest)
	v1.GET("/clients/:id", srv.HandleClientGetRequest)

	e.Logger.SetLevel(echolog.INFO)
	e.Logger.Fatal(e.Start(fmt.Sprintf("%v:%v", os.Getenv("HOST"), os.Getenv("PORT"))))
}