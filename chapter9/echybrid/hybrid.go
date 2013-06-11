package echybrid

import (
	"crypto/rand"
	"github.com/kisom/gocrypto/chapter9/ecies"
)

func GenerateKey() (prv *ecies.PrivateKey, err error) {
	return ecies.GenerateKey(rand.Reader, ecies.DefaultCurve, nil)
}

func Encrypt(pub *ecies.PublicKey, pt []byte) ([]byte, error) {
	return ecies.Encrypt(rand.Reader, pub, pt, nil, nil)
}

func Decrypt(prv *ecies.PrivateKey, ct []byte) ([]byte, error) {
	return prv.Decrypt(rand.Reader, ct, nil, nil)
}
