// aesgcm provides authenticated symmetric encryption using AES-GCM. It
// generates random nonces for each message, and prepends the nonce to
// the ciphertext.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// KeySize is size of AES-256-GCM keys in bytes.
const KeySize = 32

const nonceSize = 24

func randBytes(size int) []byte {
	p := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, p)
	if err != nil {
		p = nil
	}
	return p
}

// NewKey randomly randomly generates a new key.
func NewKey() []byte {
	return randBytes(KeySize)
}

// Encrypt applies the necessary padding to the message and encrypts it
// with AES-GCM.
func Encrypt(k, in []byte) ([]byte, bool) {
	c, err := aes.NewCipher(k)
	if err != nil {
		return nil, false
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, false
	}
	iv := randBytes(gcm.NonceSize())
	if iv == nil {
		return nil, false
	}

	gcm.Seal(in, iv, in, nil)
	return append(iv, in...), true
}

// Decrypt decrypts the message and removes any padding.
func Decrypt(k, in []byte) ([]byte, bool) {
	c, err := aes.NewCipher(k)
	if err != nil {
		return nil, false
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, false
	}

	nonceSize := gcm.NonceSize()
	if len(in) < nonceSize {
		return nil, false
	}
	gcm.Open(in[nonceSize:], in[:nonceSize], in[nonceSize:], nil)
	return in[nonceSize:], true

}
