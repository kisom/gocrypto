// Package nistecdh performs ECDH using standard library ECDSA keys.
package nistecdh

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"errors"

	"git.metacircular.net/kyle/gocrypto/chapter3/aescbc"
)

var ErrKeyExchange = errors.New("key exchange failed")

func ECDH(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	if priv.PublicKey.Curve != pub.Curve {
		return nil, ErrKeyExchange
	}

	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	if x == nil || (x.BitLen()+7)/8 < secret.KeySize {
		return nil, ErrKeyExchange
	}

	shared := sha512.Sum512(x.Bytes())
	return shared[:secret.KeySize], nil
}
