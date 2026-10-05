package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/argon2"
)

const prefix = "$argon2id$v=19$m=65536,t=3,p=1$"

func Hash(value string) (string, error) {
	if len(value) < 12 || len(value) > 256 {
		return "", errors.New("password length must be 12..256 bytes")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(value), salt, 3, 64*1024, 1, 32)
	return prefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}

// Only the supported parameter set is accepted, bounding work even for a corrupt hash.
func Verify(encoded, value string) bool {
	if len(value) > 256 || !strings.HasPrefix(encoded, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(encoded, prefix), "$")
	if len(parts) != 2 {
		return false
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[0])
	if err != nil || len(salt) != 16 {
		return false
	}
	want, err := base64.RawStdEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(value), salt, 3, 64*1024, 1, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
