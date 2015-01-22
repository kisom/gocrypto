// Package eckex uses ECDSA keys to sign ephemeral ECDH keys.
package eckex

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"

	"git.metacircular.net/kyle/gocrypto/chapter3/aesgcm"
	"git.metacircular.net/kyle/gocrypto/chapter4/nistecdh"
	"git.metacircular.net/kyle/gocrypto/util"
)

type signedKey struct {
	Public []byte
	R, S   *big.Int
}

// A Session represents a secured ephemeral session between two peers.
type Session struct {
	priv   []byte // temporarily stores private key
	shared []byte // symmetric encryption key
}

func unpackECPKIX(in []byte) (*ecdsa.PublicKey, error) {
	ipub, err := x509.ParsePKIXPublicKey(in)
	if err != nil {
		return nil, err
	}

	pub, ok := ipub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("eckex: invalid public key")
	}

	return pub, nil
}

// StartKEX prepares a new key exchange. It returns an initialised
// session handle and a signed public key that should be sent to the
// peer. peer and FinishKEX called to finalise the session. It returns a
// new session handle and a signed public key that should be sent to the
// peer.  The returned session handle has ephemeral private key data in
// it, but the shared key is not yet set up. After this call, the session
// cannot encrypt or decrypt. 
func StartKEX(signer *ecdsa.PrivateKey) (*Session, []byte, error) {
	priv, err := ecdsa.GenerateKey(signer.Curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	skey := signedKey{}
	skey.Public, err = x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	hashedPub := sha256.Sum256(skey.Public)

	skey.R, skey.S, err = ecdsa.Sign(rand.Reader, signer, hashedPub[:])
	if err != nil {
		return nil, nil, err
	}

	kex := &Session{}
	kex.priv, err = x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	out, err := asn1.Marshal(skey)
	if err != nil {
		return nil, nil, err
	}

	return kex, out, nil
}

// FinishKEX verifies the signed public key. If it is valid, it will
// carry out an ECDH key agreement, zeroise the private key, and store
// the shared key.
func (kex *Session) FinishKEX(signer *ecdsa.PublicKey, signed []byte) error {
	var skey signedKey
	rest, err := asn1.Unmarshal(signed, &skey)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("eckex: trailing data in key exchange")
	}

	hashed := sha256.Sum256(skey.Public)

	if !ecdsa.Verify(signer, hashed[:], skey.R, skey.S) {
		return errors.New("eckex: verification failure")
	}

	pub, err := unpackECPKIX(skey.Public)
	if err != nil {
		return err
	}

	priv, err := x509.ParseECPrivateKey(kex.priv)
	util.Zero(kex.priv)
	if err != nil {
		return err
	}

	kex.shared, err = nistecdh.ECDH(priv, pub)
	kex.shared = kex.shared[:32]
	return err
}

// Encrypt secures the message to the peer.
func (kex *Session) Encrypt(message []byte) ([]byte, error) {
	return secret.Encrypt(kex.shared, message)
}

// Decrypt recovers a message from the peer.
func (kex *Session) Decrypt(message []byte) ([]byte, error) {
	return secret.Decrypt(kex.shared, message)
}

// Close zeroises any remaining key material.
func (kex *Session) Close() {
	util.Zero(kex.priv)
	util.Zero(kex.shared)
}
