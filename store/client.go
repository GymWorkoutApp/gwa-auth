package store

import (
	"encoding/json"
	"errors"
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

// NewClientStore create client store
func NewClientStore() ClientStore {
	client := &ClientStoreStandard{
		redisClient: *cache.GetRedisClient(),
	}
	pong, err := client.redisClient.Ping().Result()
	if err != nil {
		fmt.Println(err)
		panic(err)
	} else {
		fmt.Println("Redis online on " + os.Getenv("REDIS_HOST") + " - " + pong)
	}

	return client
}

// ClientStore client information store
type ClientStoreStandard struct {
	redisClient redis.Client
}

// GetByID according to the ID for the client information
func (cs *ClientStoreStandard) GetByID(id string, e echo.Context) (models.ClientInfo, error) {
	result := cs.redisClient.HGet(id, "client-info")
	if result.Val() != "" {
		client := models.Client{}
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
	client := models.Client{}
	db.Where("id = ?", id).First(&client)

	if client.ID == "" {
		return nil, errors.New("ClientId not found!")
	}

	clientJson, err := jsonMarshal(client)
	if err != nil {
		return nil, err
	}

	cs.redisClient.HSet(id, "client-info", clientJson)
	cs.redisClient.Expire(id, time.Hour)

	return client, nil
}

// GetByID according to the ID for the client information
func (cs *ClientStoreStandard) Get(cli models.ClientInfo, e echo.Context) ([]models.ClientInfo, error) {
	clientJson, err := json.Marshal(cli)
	if err != nil {
		return nil, err
	}

	key := utils.Hash(clientJson)
	clients := make([]models.Client, 0)
	result := cs.redisClient.HGet(key, "client-info")
	if result.Val() != "" {
		b, err := result.Bytes()
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &clients); err != nil {
			return nil, err
		}
	} else {
		db := database.NewManageDB().Get(e.Request().Context())
		defer db.Close()

		if cli.GetID() != "" {
			db = db.Where("id = ?", cli.GetID())
		}

		if cli.GetDomain() != "" {
			db = db.Where("domain = ?", cli.GetDomain())
		}

		if cli.GetUserID() != "" {
			db = db.Where("user_id = ?", cli.GetUserID())
		}

		db.Find(&clients)

		clientsJson, err := jsonMarshal(clients)
		if err != nil {
			panic(err)
		}

		cs.redisClient.HSet(key, "client-info", clientsJson)
	}

	clientInfos := make([]models.ClientInfo, len(clients))
	for i, c := range clients {
		clientInfos[i] = c
	}

	return clientInfos, nil
}

// GetByID according to the ID for the client information
func (cs *ClientStoreStandard) RemoveByID(id string, e echo.Context) (error) {
	db := database.NewManageDB().Get(e.Request().Context())
	defer db.Close()
	err := db.Where("id = ?", "id").Delete(models.Client{}).Error
	if err != nil {
		cs.redisClient.Del(id)
	}
	return err
}

// Set set client information
func (cs *ClientStoreStandard) Create(client models.ClientInfo, e echo.Context) (models.ClientInfo,  error) {
	db := database.NewManageDB().Get(e.Request().Context())
	defer db.Close()
	err := db.Create(client).Error
	if err != nil {
		clientJson, err := jsonMarshal(client)
		if err != nil {
			return nil, err
		}
		cs.redisClient.HSet(client.GetID(), "client-info", clientJson)
	}
	return client, err
}

// Set set client information
func (cs *ClientStoreStandard) Update(client models.ClientInfo, e echo.Context) (models.ClientInfo, error) {
	db := database.NewManageDB().Get(e.Request().Context())
	defer db.Close()
	err := db.Update(client).Error
	if err != nil {
		clientJson, err := jsonMarshal(client)
		if err != nil {
			return nil, err
		}
		cs.redisClient.HSet(client.GetID(), "client-info", clientJson)
	}
	return client, err
}