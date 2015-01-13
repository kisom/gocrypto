package secret

import (
	"bytes"
	"log"
	"testing"
)

var (
	testMessage = []byte("Do not go gentle into that good night.")
	testKey     *[32]byte
)

func TestGenerateKey(t *testing.T) {
	var err error
	testKey, err = GenerateKey()
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestEncrypt(t *testing.T) {
	ct, err := Encrypt(testKey, testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	pt, err := Decrypt(testKey, ct)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(testMessage, pt) {
		log.Fatalf("messages don't match")
	}
}
