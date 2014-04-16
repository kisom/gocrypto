package salsa20

import (
	"code.google.com/p/go.crypto/salsa20"
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

const nonceSize = 24

// GenerateNonce generates a new, random XSalsa20 nonce.
var GenerateNonce = func() []byte {
	return randBytes(nonceSize)
}

func zero(in []byte) {
	for i := range in {
		in[i] = 0
	}
}

// NewKey randomly randomly generates a new key.
func NewKey() *[KeySize]byte {
	ks := randBytes(KeySize)
	if ks == nil {
		return nil
	}
	var key [KeySize]byte
	copy(key[:], ks)
	zero(ks)
	return &key
}

func Encrypt(key *[KeySize]byte, in []byte) []byte {
	nonce := GenerateNonce()
	salsa20.XORKeyStream(in, in, nonce, key)
	return append(nonce, in...)
}

func Decrypt(key *[KeySize]byte, in []byte) ([]byte, bool) {
	if len(in) < nonceSize {
		return nil, false
	}
	salsa20.XORKeyStream(in[nonceSize:], in[nonceSize:], in[:nonceSize], key)
	return in[nonceSize:], true
}
