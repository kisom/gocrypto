package nistecdh

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"git.metacircular.net/kyle/gocrypto/chapter3/aescbc"
)

var (
	alicePriv *ecdsa.PrivateKey
	bobPriv   *ecdsa.PrivateKey
)

func TestGenerateKey(t *testing.T) {
	var err error

	alicePriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}

	bobPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestExchange(t *testing.T) {
	alicePub := &alicePriv.PublicKey
	bobPub := &bobPriv.PublicKey

	abShared, err := ECDH(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("%v", err)
	}

	baShared, err := ECDH(bobPriv, alicePub)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(abShared, baShared) {
		t.Fatal("key exchange failed")
	}
}

var testMessage = []byte("do not go gentle into that good night")

func TestEncrypt(t *testing.T) {
	alicePub := &alicePriv.PublicKey
	bobPub := &bobPriv.PublicKey

	abShared, err := ECDH(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("%v", err)
	}

	out, err := secret.Encrypt(abShared, testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	baShared, err := ECDH(bobPriv, alicePub)
	if err != nil {
		t.Fatalf("%v", err)
	}

	out, err = secret.Decrypt(baShared, out)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(testMessage, out) {
		t.Fatal("decrypted message doesn't match original")
	}
}
