
package store

import (
"encoding/json"
"fmt"
"github.com/GymWorkoutApp/gwa_auth/cache"
"github.com/GymWorkoutApp/gwa_auth/database"
"github.com/GymWorkoutApp/gwa_auth/models"
"github.com/go-redis/redis"
"time"
)

// NewClientStore create user store
func NewUserStore() UserStore {
	user := &UserStoreStandard{
		redisClient: *cache.GetRedisClient(),
	}
	pong, err := user.redisClient.Ping().Result()
	if err != nil {
		panic(err)
	} else {
		fmt.Println(pong)
	}

	return user
}

// ClientStore user information store
type UserStoreStandard struct {
	redisClient redis.Client
}

// GetByID according to the ID for the user information
func (cs *UserStoreStandard) GetByID(id string) (models.UserInfo, error) {
	result := cs.redisClient.Get(id)
	if result != nil {
		user := models.User{}
		b, err := result.Bytes()
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &user); err != nil {
			return nil, err
		}
	}

	db := database.NewManageDB().Get()
	defer db.Close()
	user := models.User{}
	db.Where("id = ?", id).First(&user)

	userJson, err := jsonMarshal(user)
	if err != nil {
		return nil, err
	}

	cs.redisClient.Set(id, userJson, time.Duration(60 * 60))

	return user, nil
}

// GetByID according to the ID for the user information
func (cs *UserStoreStandard) RemoveByID(id string) (error) {
	db := database.NewManageDB().Get()
	defer db.Close()
	err := db.Where("id = ?", "id").Delete(models.User{}).Error
	if err != nil {
		cs.redisClient.Del(id)
	}
	return err
}

// Set set user information
func (cs *UserStoreStandard) Create(user models.UserInfo) (models.UserInfo,  error) {
	db := database.NewManageDB().Get()
	defer db.Close()
	err := db.Create(user).Error
	if err != nil {
		userJson, err := jsonMarshal(user)
		if err != nil {
			return nil, err
		}
		cs.redisClient.Set(user.GetID(), userJson, time.Duration(60 * 60))
	}
	return user, err
}

// Set set user information
func (cs *UserStoreStandard) Update(user models.UserInfo) (models.UserInfo, error) {
	db := database.NewManageDB().Get()
	defer db.Close()
	err := db.Update(user).Error
	if err != nil {
		userJson, err := jsonMarshal(user)
		if err != nil {
			return nil, err
		}
		cs.redisClient.Set(user.GetID(), userJson, time.Duration(60 * 60))
	}
	return user, err
}