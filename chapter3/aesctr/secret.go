// Package secret contains an example of using AES-256-GCM.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"

	"git.metacircular.net/kyle/gocrypto/util"
)

const (
	NonceSize = aes.BlockSize
	MACSize   = 32
	CKeySize  = 32 // Cipher key size - AES-256
	MKeySize  = 32 // HMAC key size - HMAC-SHA-256
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

// Encrypt secures a message using AES-CTR-HMAC-SHA-256 with a random
// nonce.
func Encrypt(key, message []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrEncrypt
	}

	nonce, err := util.RandBytes(NonceSize)
	if err != nil {
		return nil, ErrEncrypt
	}

	ct := make([]byte, len(message))

	// NewCipher only returns an error with an invalid key size,
	// but the key size was checked at the beginning of the function.
	c, _ := aes.NewCipher(key[:CKeySize])
	ctr := cipher.NewCTR(c, nonce)
	ctr.XORKeyStream(ct, message)

	h := hmac.New(sha256.New, key[CKeySize:])
	ct = append(nonce, ct...)
	h.Write(ct)
	ct = h.Sum(ct)
	return ct, nil
}

// Decrypt recovers a message using AES-CTR-HMAC-SHA-256 where the nonce
// is prepended.
func Decrypt(key, message []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrDecrypt
	}

	if len(message) <= (NonceSize + MACSize) {
		return nil, ErrDecrypt
	}

	macStart := len(message) - MACSize
	tag := message[macStart:]
	out := make([]byte, macStart-NonceSize)
	message = message[:macStart]

	h := hmac.New(sha256.New, key[CKeySize:])
	h.Write(message)
	mac := h.Sum(nil)
	if !hmac.Equal(mac, tag) {
		return nil, ErrDecrypt
	}

	c, _ := aes.NewCipher(key[:CKeySize])
	ctr := cipher.NewCTR(c, message[:NonceSize])
	ctr.XORKeyStream(out, message[NonceSize:])
	return out, nil
}
