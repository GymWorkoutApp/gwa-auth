package utils


import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"
)

func Hash(data interface{}) string {
	hasher := sha1.New()
	hasher.Write([]byte(fmt.Sprintf("%v", data)))
	key := os.Getenv("KEY_HASH")
	if key == "" {
		panic("KEY_HASH not found")
	}
	sha := base64.URLEncoding.EncodeToString(hasher.Sum([]byte(key)))
	return sha
}