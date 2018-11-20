package cache


import (
	"github.com/go-redis/redis"
	"os"
	"sync"
	"sync/atomic"
)


var initialized uint32
var mu sync.Mutex
var instance *redis.Client

func GetRedisClient() *redis.Client {

	if atomic.LoadUint32(&initialized) == 1 {
		return instance
	}

	mu.Lock()
	defer mu.Unlock()

	if initialized == 0 {
		instance = redis.NewClient(&redis.Options{
			Addr: os.Getenv("REDIS_HOST"),
			DB: 15,
		})
		atomic.StoreUint32(&initialized, 1)
	}

	return instance
}