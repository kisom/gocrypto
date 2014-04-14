// aesctr provides unauthenticated symmetric encryption using AES-CTR. It
// generates random nonces for each message, and prepends the nonce to
// the ciphertext.
package aesctr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// KeySize is size of AES-256-CTR keys in bytes.
const KeySize = 32

func randBytes(size int) []byte {
	p := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, p)
	if err != nil {
		p = nil
	}
	return p
}

// GenerateIV provides new IVs. The default function returns randomly
// generated IVs.
var GenerateIV = func() []byte {
	return randBytes(aes.BlockSize)
}

// NewKey randomly randomly generates a new key.
func NewKey() []byte {
	return randBytes(KeySize)
}

// Encrypt applies the necessary padding to the message and encrypts it
// with AES-CTR.
func Encrypt(k, in []byte) ([]byte, bool) {
	iv := GenerateIV()
	if iv == nil {
		return nil, false
	}

	c, err := aes.NewCipher(k)
	if err != nil {
		return nil, false
	}

	ctr := cipher.NewCTR(c, iv)
	ctr.XORKeyStream(in, in)
	return append(iv, in...), true
}

// Decrypt decrypts the message and removes any padding.
func Decrypt(k, in []byte) ([]byte, bool) {
	if len(in) < aes.BlockSize {
		return nil, false
	}

	c, err := aes.NewCipher(k)
	if err != nil {
		return nil, false
	}

	ctr := cipher.NewCTR(c, in[:aes.BlockSize])
	ctr.XORKeyStream(in[aes.BlockSize:], in[aes.BlockSize:])
	return in[aes.BlockSize:], true

}
