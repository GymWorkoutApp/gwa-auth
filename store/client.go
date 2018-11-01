package store

import (
	"errors"
	"github.com/GymWorkoutApp/gwa_auth.server/models"
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
func (cs *ClientStoreMemory) Set(id string, cli models.ClientInfo) (err error) {
	cs.Lock()
	defer cs.Unlock()
	cs.data[id] = cli
	return
}
