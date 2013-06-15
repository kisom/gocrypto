package dhhybrid

import (
	"fmt"
	"github.com/gokyle/dhkam"
	"github.com/kisom/gocrypto/chapter9/authsym"
)

var keyMaterialSize = authsym.SymKeyLen + authsym.MacKeyLen
var ErrInvalidKEKParams = fmt.Errorf("invalid KEK parameters")

func Encrypt(prv *dhkam.PrivateKey, kek *dhkam.KEK, pub *dhkam.PublicKey, m []byte) (out []byte, err error) {
	key, err := prv.CEK(kek)
	if err != nil {
		return
	}
	out, err = authsym.Encrypt(key[:authsym.SymKeyLen], key[authsym.SymKeyLen:], m)
	return
}

func Decrypt(prv *dhkam.PrivateKey, kek *dhkam.KEK, pub *dhkam.PublicKey, m []byte) (out []byte, err error) {
	key, err := prv.CEK(kek)
	if err != nil {
		return
	}
	out, err = authsym.Decrypt(key[:authsym.SymKeyLen], key[authsym.SymKeyLen:], m)
	return
}
