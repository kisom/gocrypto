// Package secret contains an example of using AES-256-GCM.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"git.metacircular.net/kyle/gocrypto/util"
)

const (
	KeySize   = 32
	NonceSize = 12
)

var (
	ErrEncrypt = errors.New("secret: encryption failed")
	ErrDecrypt = errors.New("secret: decryption failed")
)

// GenerateKey generates a new AES-256 key.
func GenerateKey() ([]byte, error) {
	return util.RandBytes(KeySize)
}

// GenerateNonce generates a new AES-GCM nonce.
func GenerateNonce() ([]byte, error) {
	return util.RandBytes(NonceSize)
}

// Encrypt secures a message using AES-GCM.
func Encrypt(key, message []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrEncrypt
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, ErrEncrypt
	}

	nonce, err := GenerateNonce()
	if err != nil {
		return nil, ErrEncrypt
	}

	// Seal will append the output to the first argument; the usage
	// here appends the ciphertext to the nonce. The final parameter
	// is any additional data to be authenticated.
	out := gcm.Seal(nonce, nonce, message, nil)
	return out, nil
}

// Decrypt recovers a message secured using AES-GCM.
func Decrypt(key, message []byte) ([]byte, error) {
	if len(message) <= NonceSize {
		return nil, ErrDecrypt
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecrypt
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, ErrDecrypt
	}

	nonce := make([]byte, NonceSize)
	copy(nonce, message)

	out, err := gcm.Open(nil, nonce, message[NonceSize:], nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}
