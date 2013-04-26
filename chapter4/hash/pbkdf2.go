package hash

import (
	"code.google.com/p/go.crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"io"
)

var (
	IterationCount = 16384
	KeySize        = 32
	SaltLength     = 128
)

type PasswordKey struct {
	Salt []byte
	Key  []byte
}

func generateSalt(chars int) (salt []byte, err error) {
	salt = make([]byte, chars)
	_, err = io.ReadFull(rand.Reader, salt)
	return
}

// DeriveKey generates a salt and returns a hashed version of the password.
func DeriveKey(password string) *PasswordKey {
	salt, err := generateSalt(SaltLength)
	if err != nil {
		return nil
	}
	return DeriveKeyWithSalt(password, salt)
}

// DeriveKeyWithSalt hashes the password with the specified salt.
func DeriveKeyWithSalt(password string, salt []byte) (ph *PasswordKey) {
	key := pbkdf2.Key([]byte(password), salt, IterationCount,
		KeySize, sha512.New)
	return &PasswordKey{salt, key}
}

// MatchPassword compares the input password with the password hash.
// It returns true if they match.
func MatchPassword(password string, pk *PasswordKey) bool {
	matched := 0
	new_key := DeriveKeyWithSalt(password, pk.Salt)

	size := len(new_key.Key)
	if size > len(pk.Key) {
		size = len(pk.Key)
	}

	for i := 0; i < size; i++ {
		matched += subtle.ConstantTimeByteEq(new_key.Key[i], pk.Key[i])
	}

	passed := matched == size
	if len(new_key.Key) != len(pk.Key) {
		return false
	}
	return passed
}
