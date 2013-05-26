package pkc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

const KeySize = 3072
var defaultLabel = []byte{}

func MaxMessageLength(key *rsa.PrivateKey) int64 {
	if key == nil {
		return 0
	}
	msgLen := key.N.Int64()
	msgLen -= (2 * sha256.Size + 2)
	return msgLen
}

func GenerateKey() (key *rsa.PrivateKey, err error) {
	return rsa.GenerateKey(rand.Reader, KeySize)
}

func Encrypt(pub *rsa.PublicKey, pt []byte) (ct []byte, err error) {
	hash := sha256.New()
	ct, err = rsa.EncryptOAEP(hash, rand.Reader, pub, pt, defaultLabel)
	return
}

func Decrypt(prv *rsa.PrivateKey, ct []byte) (pt []byte, err error) {
	hash := sha256.New()
	ct, err = rsa.DecryptOAEP(hash, rand.Reader, prv, ct, defaultLabel)
	return
}
