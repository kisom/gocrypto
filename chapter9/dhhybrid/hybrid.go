package dhhybrid

import (
	"crypto/rand"
	"github.com/gokyle/dhkam"
	"github.com/kisom/gocrypto/chapter9/authsym"
)

var keyMaterialSize = authsym.SymKeyLen + authsym.MacKeyLen

func Encrypt(prv *dhkam.PrivateKey, pub *dhkam.PublicKey, m []byte) (out []byte, err error) {
	key, err := prv.SharedKey(rand.Reader, pub, keyMaterialSize)
	if err != nil {
		return
	}

	out, err = authsym.Encrypt(key[:authsym.SymKeyLen], key[authsym.SymKeyLen:], m)
	return
}

func Decrypt(prv *dhkam.PrivateKey, pub *dhkam.PublicKey, m []byte) (out []byte, err error) {
	key, err := prv.SharedKey(rand.Reader, pub, keyMaterialSize)
	if err != nil {
		return
	}

	out, err = authsym.Decrypt(key[:authsym.SymKeyLen], key[authsym.SymKeyLen:], m)
	return
}
