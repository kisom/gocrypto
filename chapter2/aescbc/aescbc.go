// aescbc provides unauthenticated symmetric encryption using AES-CBC. It
// generates a random IV for each message, and prepends the IV to the
// ciphertext.
package aescbc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// KeySize is size of AES-256-CBC keys in bytes.
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
// with AES-CBC.
func Encrypt(k, in []byte) ([]byte, bool) {
	in = Pad(in)
	iv := GenerateIV()
	if iv == nil {
		return nil, false
	}

	c, err := aes.NewCipher(k)
	if err != nil {
		return nil, false
	}

	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(in, in)
	return append(iv, in...), true
}

// Decrypt decrypts the message and removes any padding.
func Decrypt(k, in []byte) ([]byte, bool) {
	if len(in) == 0 || len(in)%aes.BlockSize != 0 {
		return nil, false
	}

	c, err := aes.NewCipher(k)
	if err != nil {
		return nil, false
	}

	cbc := cipher.NewCBCDecrypter(c, in[:aes.BlockSize])
	cbc.CryptBlocks(in[aes.BlockSize:], in[aes.BlockSize:])
	out := Unpad(in[aes.BlockSize:])
	if out == nil {
		return nil, false
	}
	return out, true

}
