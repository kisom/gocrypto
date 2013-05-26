package bench

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

const RSAKeySize = 3072

var defaultLabel []byte = nil

func MaxMessageLength(key *rsa.PublicKey) int {
	if key == nil {
		return 0
	}
	return key.N.BitLen() - (2 * sha256.Size) - 2
}

func GenerateRSAKey() (key *rsa.PrivateKey, err error) {
	return rsa.GenerateKey(rand.Reader, RSAKeySize)
}

func RSAEncrypt(pub *rsa.PublicKey, pt []byte) (ct []byte, err error) {
	if len(ct) > MaxMessageLength(pub) {
		err = fmt.Errorf("message is too long")
		return
	}

	hash := sha256.New()
	ct, err = rsa.EncryptOAEP(hash, rand.Reader, pub, pt, defaultLabel)
	return
}

func RSADecrypt(prv *rsa.PrivateKey, ct []byte) (pt []byte, err error) {
	hash := sha256.New()
	pt, err = rsa.DecryptOAEP(hash, rand.Reader, prv, ct, defaultLabel)
	return
}

func RSAEncryptDecrypt(prv *rsa.PrivateKey, msg []byte) (err error) {
	pub := &prv.PublicKey

	ct, err := RSAEncrypt(pub, msg)
	if err != nil {
		return
	}

	pt, err := RSADecrypt(prv, ct)
	if err != nil {
		return
	} else if !bytes.Equal(pt, msg) {
		err = fmt.Errorf("invalid decryption")
	}
	return
}
