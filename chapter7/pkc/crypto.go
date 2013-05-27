package pkc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

const KeySize = 3072

var defaultLabel = []byte{}

func MaxMessageLength(key *rsa.PublicKey) int {
	if key == nil {
		return 0
	}
	return (key.N.BitLen() / 8) - (2 * sha256.Size) - 2
}

func GenerateKey() (key *rsa.PrivateKey, err error) {
	return rsa.GenerateKey(rand.Reader, KeySize)
}

func Encrypt(pub *rsa.PublicKey, pt []byte) (ct []byte, err error) {
	if len(ct) > MaxMessageLength(pub) {
		err = fmt.Errorf("message is too long")
		return
	}

	hash := sha256.New()
	ct, err = rsa.EncryptOAEP(hash, rand.Reader, pub, pt, defaultLabel)
	return
}

func Decrypt(prv *rsa.PrivateKey, ct []byte) (pt []byte, err error) {
	hash := sha256.New()
	pt, err = rsa.DecryptOAEP(hash, rand.Reader, prv, ct, defaultLabel)
	return
}
