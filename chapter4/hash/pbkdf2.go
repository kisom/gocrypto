package hash

import (
	_pbkdf2 "code.google.com/p/go.crypto/pbkdf2"
	"crypto/rand"
	"crypto/subtle"
)

var (
	IterationCount = 16384
	KeySize        = 32
	SaltLength     = 128
)

type PasswordHash struct {
	Salt []byte
	Hash []byte
}

func generateSalt(chars int) (salt []byte) {
	saltBytes := make([]byte, chars)
	nRead, err := rand.Read(saltBytes)
	if err != nil {
		salt = []byte{}
	} else if nRead < chars {
		salt = []byte{}
	} else {
		salt = saltBytes
	}
	return
}

// HashPassword generates a salt and returns a hashed version of the password.
func HashPassword(password string) *PasswordHash {
	salt := generateSalt(SaltLength)
	return HashPasswordWithSalt(password, salt)
}

// HashPasswordWithSalt hashes the password with the specified salt.
func HashPasswordWithSalt(password string, salt []byte) (ph *PasswordHash) {
	hash := _pbkdf2.Key([]byte(password), salt, IterationCount,
		KeySize, DefaultAlgo.New)
	return &PasswordHash{hash, salt}
}

// MatchPassword compares the input password with the password hash.
// It returns true if they match.
func MatchPassword(password string, ph *PasswordHash) bool {
	matched := 0
	new_hash := HashPasswordWithSalt(password, ph.Salt)

	size := len(new_hash.Hash)
	if size > len(ph.Hash) {
		size = len(ph.Hash)
	}

	for i := 0; i < size; i++ {
		matched += subtle.ConstantTimeByteEq(new_hash.Hash[i], ph.Hash[i])
	}

	passed := matched == size
	if len(new_hash.Hash) != len(ph.Hash) {
		return false
	}
	return passed
}
