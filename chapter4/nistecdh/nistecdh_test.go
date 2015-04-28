package nistecdh

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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

func TestBadPubs(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}

	bad1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}

	bad2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
	bad2.Curve = elliptic.P521()

	var bad3 *ecdsa.PublicKey
	if _, err = ECDH(priv, bad3); err == nil {
		t.Fatalf("ECDH should fail with nil key")
	} else if _, err = ECDH(priv, &bad1.PublicKey); err == nil {
		t.Fatalf("ECDH should fail with mismatched curve")
	} else if _, err = ECDH(priv, &bad2.PublicKey); err == nil {
		t.Fatalf("ECDH should fail with wrong curve")
	}
}

func TestParse(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("%v")
	}

	rsaPub, err := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	if err != nil {
		t.Fatalf("%v")
	}

	_, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("%v")
	}

	pub := elliptic.Marshal(elliptic.P256(), x, y)
	if err != nil {
		t.Fatalf("%v")
	}

	if _, err = ParseECPublicKey(rsaPub); err == nil {
		t.Fatal("Expected RSA public key to fail to parse as a PKIX EC key")
	}

	if _, err = ParseECPublicKey(pub); err == nil {
		t.Fatal("Expected EC public key to fail to parse as a PKIX EC key")
	}

	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("%v")
	}

	pub, err = x509.MarshalPKIXPublicKey(&ecdsaPriv.PublicKey)
	if err != nil {
		t.Fatalf("%v")
	}

	_, err = ParseECPublicKey(pub)
	if err != nil {
		t.Fatalf("%v")
	}
}
