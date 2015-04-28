// Package nistecdh performs ECDH using standard library ECDSA keys.
package nistecdh

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"errors"

	"git.metacircular.net/kyle/gocrypto/chapter3/aescbc"
)

// ErrKeyExchange is returned if the key exchange fails.
var ErrKeyExchange = errors.New("key exchange failed")

// ECDH computes a shared key from a private key and a peer's public key.
func ECDH(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil || priv == nil {
		return nil, ErrKeyExchange
	} else if priv.Curve != pub.Curve {
		return nil, ErrKeyExchange
	} else if !priv.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, ErrKeyExchange
	}

	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	if x == nil {
		return nil, ErrKeyExchange
	}

	shared := sha512.Sum512(x.Bytes())
	return shared[:secret.KeySize], nil
}

// ParseECPublicKey decodes a PKIX-encoded EC public key.
func ParseECPublicKey(in []byte) (*ecdsa.PublicKey, error) {
	// UnmarshalPKIXPublicKey returns an interface{}.
	pub, err := x509.ParsePKIXPublicKey(in)
	if err != nil {
		return nil, err
	}

	ecpub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid EC public key")
	}

	return ecpub, nil
}
