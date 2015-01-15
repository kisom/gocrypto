// Package secret contains an example of using AES-256-GCM.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"errors"

	"git.metacircular.net/kyle/gocrypto/util"
)

const (
	NonceSize = aes.BlockSize
	MACSize   = 48
	CKeySize  = 32 // Cipher key size - AES-256
	MKeySize  = 48 // HMAC key size - HMAC-SHA-384
)

var KeySize = CKeySize + MKeySize

var (
	ErrEncrypt = errors.New("secret: encryption failed")
	ErrDecrypt = errors.New("secret: decryption failed")
)

// GenerateKey generates a new AES-256 and HMAC-SHA-384 key.
func GenerateKey() ([]byte, error) {
	return util.RandBytes(KeySize)
}

// GenerateNonce generates a new AES-CTR nonce.
func GenerateNonce() ([]byte, error) {
	return util.RandBytes(NonceSize)
}
