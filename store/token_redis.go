package store

import (
	"github.com/GymWorkoutApp/gwap-auth/cache"
	"github.com/GymWorkoutApp/gwap-auth/models"
	"github.com/GymWorkoutApp/gwap-auth/utils/uuid"
	"time"

	"github.com/go-redis/redis"
	"github.com/json-iterator/go"
)

var (
	_             				    = TokenRedisStore{}
	jsonMarshal                     = jsoniter.Marshal
	jsonUnmarshal                   = jsoniter.Unmarshal
)

// NewRedisStore create an instance of a cache store
func NewRedisStore() *TokenRedisStore {
	return NewRedisStoreWithCli()
}

// NewRedisStoreWithCli create an instance of a cache store
func NewRedisStoreWithCli() *TokenRedisStore {
	store := &TokenRedisStore{
		cli: *cache.GetRedisClient(),
	}

	//if len(keyNamespace) > 0 {
	//	store.ns = keyNamespace[0]
	//}
	return store
}

//// NewRedisClusterStore create an instance of a cache cluster store
//func NewRedisClusterStore(opts *ClusterOptions) *TokenRedisStore {
//	if opts == nil {
//		panic("options cannot be nil")
//	}
//	return NewRedisClusterStoreWithCli(redis.NewClusterClient(opts.redisClusterOptions()), opts.KeyNamespace)
//}
//
//// NewRedisClusterStoreWithCli create an instance of a cache cluster store
//func NewRedisClusterStoreWithCli(cli *redis.ClusterClient, keyNamespace ...string) *TokenRedisStore {
//	store := &TokenRedisStore{
//		cli: *cache.GetRedisClient(),
//	}
//
//	//if len(keyNamespace) > 0 {
//	//	store.ns = keyNamespace[0]
//	//}
//	return store
//}



// TokenRedisStore cache token store
type TokenRedisStore struct {
	cli redis.Client
	ns  string
}

// Close close the store
func (s *TokenRedisStore) Close() error {
	return s.cli.Close()
}

// Create Create and store the new token information
func (s *TokenRedisStore) Create(info models.TokenInfo) (err error) {
	ct := time.Now()
	jv, err := jsonMarshal(info)
	if err != nil {
		return
	}

	pipe := s.cli.TxPipeline()
	if code := info.GetCode(); code != "" {
		pipe.Set(code, jv, info.GetCodeExpiresIn())
	} else {
		basicID := uuid.Must(uuid.NewRandom()).String()
		aexp := info.GetAccessExpiresIn()
		rexp := aexp

		if refresh := info.GetRefresh(); refresh != "" {
			rexp = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn()).Sub(ct)
			if aexp.Seconds() > rexp.Seconds() {
				aexp = rexp
			}
			pipe.Set(refresh, basicID, rexp)
		}

		pipe.Set(info.GetAccess(), basicID, aexp)
		pipe.Set(basicID, jv, rexp)
	}

	if _, verr := pipe.Exec(); verr != nil {
		err = verr
	}
	return
}

// remove
func (s *TokenRedisStore) remove(key string) (err error) {
	_, verr := s.cli.Del(key).Result()
	if verr != redis.Nil {
		err = verr
	}
	return
}

// RemoveByCode Use the authorization code to delete the token information
func (s *TokenRedisStore) RemoveByCode(code string) (err error) {
	err = s.remove(code)
	return
}

// RemoveByAccess Use the access token to delete the token information
func (s *TokenRedisStore) RemoveByAccess(access string) (err error) {
	err = s.remove(access)
	return
}

// RemoveByRefresh Use the refresh token to delete the token information
func (s *TokenRedisStore) RemoveByRefresh(refresh string) (err error) {
	err = s.remove(refresh)
	return
}

func (s *TokenRedisStore) getData(key string) (ti models.TokenInfo, err error) {
	result := s.cli.Get(key)
	if verr := result.Err(); verr != nil {
		if verr == redis.Nil {
			return
		}
		err = verr
		return
	}

	iv, err := result.Bytes()
	if err != nil {
		return
	}

	var tm models.Token
	if verr := jsonUnmarshal(iv, &tm); verr != nil {
		err = verr
		return
	}

	ti = &tm
	return
}

func (s *TokenRedisStore) getBasicID(token string) (basicID string, err error) {
	tv, verr := s.cli.Get(token).Result()
	if verr != nil {
		if verr == redis.Nil {
			return
		}
		err = verr
		return
	}
	basicID = tv
	return
}

// GetByCode Use the authorization code for token information data
func (s *TokenRedisStore) GetByCode(code string) (ti models.TokenInfo, err error) {
	ti, err = s.getData(code)
	return
}

// GetByAccess Use the access token for token information data
func (s *TokenRedisStore) GetByAccess(access string) (ti models.TokenInfo, err error) {
	basicID, err := s.getBasicID(access)
	if err != nil || basicID == "" {
		return
	}
	ti, err = s.getData(basicID)
	return
}

// GetByRefresh Use the refresh token for token information data
func (s *TokenRedisStore) GetByRefresh(refresh string) (ti models.TokenInfo, err error) {
	basicID, err := s.getBasicID(refresh)
	if err != nil || basicID == "" {
		return
	}
	ti, err = s.getData(basicID)
	return
}
