package store

import (
	"errors"
	"github.com/GymWorkoutApp/gwa_auth/database"
	"github.com/GymWorkoutApp/gwa_auth/models"
	"sync"
)

// NewClientStore create client store
func NewClientStore() ClientStore {
	return &ClientStoreMemory{
		data: make(map[string]models.ClientInfo),
	}
}

// ClientStore client information store
type ClientStoreMemory struct {
	sync.RWMutex
	data map[string]models.ClientInfo
}

// GetByID according to the ID for the client information
func (cs *ClientStoreMemory) GetByID(id string) (cli models.ClientInfo, err error) {
	cs.RLock()
	defer cs.RUnlock()
	if c, ok := cs.data[id]; ok {
		cli = c
		return
	}
	err = errors.New("not found")
	return
}

// Set set client information
func (cs *ClientStoreMemory) Set(cli models.ClientInfo) (err error) {
	cs.Lock()
	defer cs.Unlock()
	cs.data[cli.GetID()] = cli
	return
}



// NewClientStore create client store
func NewClientStoreDB() ClientStore {
	return &ClientStoreDB{}
}

// ClientStore client information store
type ClientStoreDB struct {

}

// GetByID according to the ID for the client information
func (cs *ClientStoreDB) GetByID(id string) (models.ClientInfo, error) {
	db := database.NewManageDB().Get()
	defer db.Close()
	client := models.Client{}
	db.Where("id = ?", id).First(&client)
	return client, nil
}

// Set set client information
func (cs *ClientStoreDB) Set(client models.ClientInfo) (err error) {
	db := database.NewManageDB().Get()
	defer db.Close()
	return db.Save(client).Error
}