package main

import (
	"fmt"
	"github.com/GymWorkoutApp/gwa_auth.server/cache"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"os"

	"github.com/GymWorkoutApp/gwa_auth.server/errors"
	"github.com/GymWorkoutApp/gwa_auth.server/generates"
	"github.com/GymWorkoutApp/gwa_auth.server/manager"
	"github.com/GymWorkoutApp/gwa_auth.server/models"
	"github.com/GymWorkoutApp/gwa_auth.server/server"
	"github.com/GymWorkoutApp/gwa_auth.server/store"
)

func main() {

	manager := manager.NewDefaultManager()
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate([]byte("00000000"), jwt.SigningMethodHS512))

	// token memory store
	manager.MapTokenStorage(redis.NewRedisStore(&redis.Options{
		Addr: "127.0.0.1:6379",
		DB: 15,
	}))

	// client memory store
	clientStore := store.NewClientStore()
	clientStore.Set("000000", &models.Client{
		ID:     "000000",
		Secret: "999999",
		Domain: "http://localhost",
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewDefaultServer(manager)
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