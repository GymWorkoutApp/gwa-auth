package store

import (
	"encoding/json"
	"fmt"
	"github.com/GymWorkoutApp/gwap-auth/cache"
	"github.com/GymWorkoutApp/gwap-auth/database"
	"github.com/GymWorkoutApp/gwap-auth/models"
	"github.com/GymWorkoutApp/gwap-auth/utils"
	"github.com/go-redis/redis"
	"github.com/labstack/echo"
	"os"
	"time"
)

// NewUserStore create client store
func NewUserStore() UserStore {
	userStr := &UserStoreStandard{
		redisClient: *cache.GetRedisClient(),
	}
	pong, err := userStr.redisClient.Ping().Result()
	if err != nil {
		fmt.Println(err)
		panic(err)
	} else {
		fmt.Println("Redis online on " + os.Getenv("REDIS_HOST") + " - " + pong)
	}

	return userStr
}

// UserStore client information store
type UserStoreStandard struct {
	redisClient redis.Client
}

// GetByID according to the ID for the client information
func (cs *UserStoreStandard) GetByID(id string, e echo.Context) (models.UserInfo, error) {
	result := cs.redisClient.HGet(id, "user-info")
	if result.Val() != "" {
		client := models.User{}
		b, err := result.Bytes()
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &client); err != nil {
			return nil, err
		}
		return client, nil
	}

	db := database.NewManageDB().Get(e.Request().Context())
	defer db.Close()
	client := models.User{}
	db.Where("id = ?", id).First(&client)

	clientJson, err := jsonMarshal(client)
	if err != nil {
		return nil, err
	}

	cs.redisClient.HSet(id, "user-info", clientJson)
	cs.redisClient.Expire(id, time.Hour)

	return client, nil
}

// GetByID according to the ID for the client information
func (cs *UserStoreStandard) GetByUsername(username string, e echo.Context) (models.UserInfo, error) {
	result := cs.redisClient.HGet(username, "user-info")
	if result.Val() != "" {
		client := models.User{}
		b, err := result.Bytes()
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &client); err != nil {
			return nil, err
		}
		return client, nil
	}

	db := database.NewManageDB().Get(e.Request().Context())
	defer db.Close()
	client := models.User{}
	db.Where("username = ?", username).First(&client)

	clientJson, err := jsonMarshal(client)
	if err != nil {
		return nil, err
	}

	cs.redisClient.HSet(username, "user-info", clientJson)
	cs.redisClient.Expire(username, time.Hour)

	return client, nil
}

// GetByID according to the ID for the client information
func (cs *UserStoreStandard) Get(user models.UserInfo, e echo.Context) ([]models.UserInfo, error) {
	clientJson, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}

	key := utils.Hash(clientJson)
	users := make([]models.User, 0)
	result := cs.redisClient.HGet(key, "user-info")
	if result.Val() != "" {
		b, err := result.Bytes()
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &users); err != nil {
			return nil, err
		}
	} else {
		db := database.NewManageDB().Get(e.Request().Context())
		defer db.Close()

		if user.GetID() != "" {
			db = db.Where("id = ?", user.GetID())
		}

		if user.GetName() != "" {
			db = db.Where("domain = ?", user.GetName())
		}

		db.Find(&users)

		usersJson, err := jsonMarshal(users)
		if err != nil {
			panic(err)
		}

		cs.redisClient.HSet(key, "user-info", usersJson)
	}

	usersInfo := make([]models.UserInfo, len(users))
	for i, c := range users {
		usersInfo[i] = c
	}

	return usersInfo, nil
}

// GetByID according to the ID for the client information
func (cs *UserStoreStandard) RemoveByID(id string, e echo.Context) (error) {
	db := database.NewManageDB().Get(e.Request().Context())
	defer db.Close()
	err := db.Where("id = ?", "id").Delete(models.User{}).Error
	if err != nil {
		cs.redisClient.Del(id)
	}
	return err
}

// Set set client information
func (cs *UserStoreStandard) Create(user models.UserInfo, e echo.Context) (models.UserInfo,  error) {
	db := database.NewManageDB().Get(e.Request().Context())
	defer db.Close()
	err := db.Create(user).Error
	if err != nil {
		userJson, err := jsonMarshal(user)
		if err != nil {
			return nil, err
		}
		cs.redisClient.HSet(user.GetID(), "user-info", userJson)
	}
	return user, err
}

// Set set client information
func (cs *UserStoreStandard) Update(user models.UserInfo, e echo.Context) (models.UserInfo, error) {
	db := database.NewManageDB().Get(e.Request().Context())
	defer db.Close()
	err := db.Update(user).Error
	if err != nil {
		userJson, err := jsonMarshal(user)
		if err != nil {
			return nil, err
		}
		cs.redisClient.HSet(user.GetID(), "user-info", userJson)
	}
	return user, err
}