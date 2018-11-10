package main

import (
	"fmt"
	"github.com/GymWorkoutApp/gwa_auth/cache"
	"github.com/GymWorkoutApp/gwa_auth/database"
	"github.com/GymWorkoutApp/gwa_auth/models"
	"github.com/GymWorkoutApp/gwa_auth/store"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"os"

	"github.com/GymWorkoutApp/gwa_auth/errors"
	"github.com/GymWorkoutApp/gwa_auth/generates"
	"github.com/GymWorkoutApp/gwa_auth/manager"
	"github.com/GymWorkoutApp/gwa_auth/server"
)

func main() {

	managerServer := manager.NewDefaultManager()
	managerServer.MapAccessGenerate(generates.NewJWTAccessGenerate([]byte("00000000"), jwt.SigningMethodHS512))

	// token memory store
	managerServer.MapTokenStorage(redis.NewRedisStore(&redis.Options{
		Addr: "127.0.0.1:6379",
		DB: 15,
	}))

	srv := server.NewDefaultServer(managerServer)

	db := database.NewManageDB().Get()
	defer db.Close()
	db.AutoMigrate(&models.Client{})

	// client memory store
	clientStore := store.NewClientStoreDB()
	clientStore.Set(&models.Client{
		Secret: "999999",
		Domain: "http://localhost",
	})
	managerServer.MapClientStorage(clientStore)

	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		re = &errors.Response{Error: err, StatusCode: 500, Description: err.Error()}
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		srv.HandleTokenRequest(w, r)
	})

	http.HandleFunc("/introspect", func (w http.ResponseWriter, r *http.Request) {
		srv.HandleIntrospectRequest(w, r)
	})

	port := os.Getenv("PORT")
	log.Println(fmt.Sprintf("Running on :%v", port))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%v",port), nil))
}