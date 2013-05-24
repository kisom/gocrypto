package bench

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
)

const AESKeySize = 16
const RSAKeySize = 3072

func Random(size int) (b []byte, err error) {
	b = make([]byte, size)
	_, err = io.ReadFull(rand.Reader, b)
	return
}

func generateAESKey() (key []byte, err error) {
	return Random(AESKeySize)
}

func generateRSAKey() (key *rsa.PrivateKey, err error) {
	key, err = rsa.GenerateKey(rand.Reader, RSAKeySize)
	return
}
