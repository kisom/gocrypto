package session

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

var (
	alicePub, alicePriv *[32]byte
	bobPub, bobPriv     *[32]byte
)

func TestGenerateKeys(t *testing.T) {
	var err error

	alicePub, alicePriv, err = box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}

	bobPub, bobPriv, err = box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

var (
	testMessage = []byte("do not go gentle into that good night")
	testSecured []byte

	aliceSession, bobSession *Session
)

func TestEncrypt(t *testing.T) {
	var err error
	aliceSession = NewSession(alicePriv, bobPub)
	testSecured, err = aliceSession.Encrypt(testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestDecrypt(t *testing.T) {
	bobSession = NewSession(bobPriv, alicePub)
	out, err := bobSession.Decrypt(testSecured)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(out, testMessage) {
		t.Fatal("recovered message doesn't match original")
	}
}

func TestEncryptSeveral(t *testing.T) {
	var err error

	for i := 0; i < 10; i++ {
		testSecured, err = aliceSession.Encrypt(testMessage)
		if err != nil {
			t.Fatalf("%v", err)
		}
	}

	out, err := bobSession.Decrypt(testSecured)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(out, testMessage) {
		t.Fatal("recovered message doesn't match original")
	}
}

func TestCounterRegress(t *testing.T) {
	var err error
	aliceSession.LastSent = 1
	aliceSession = NewSession(alicePriv, bobPub)
	testSecured, err = aliceSession.Encrypt(testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = bobSession.Decrypt(testSecured)
	if err == nil {
		t.Fatal("decrypt should fail with bad message counter")
	}
}
