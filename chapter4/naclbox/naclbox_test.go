package naclbox

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

var (
	alicePub, alicePriv *[32]byte
)

func TestGenerateKeys(t *testing.T) {
	var err error

	alicePub, alicePriv, err = box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

var (
	testMessage = []byte("do not go gentle into that good night")
	testSecured []byte
)

func TestEncrypt(t *testing.T) {
	out, err := Encrypt(alicePub, testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}
	testSecured = out
}

func TestDecrypt(t *testing.T) {
	out, err := Decrypt(alicePriv, testSecured)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(testMessage, out) {
		t.Fatal("recovered message doesn't match original")
	}
}
