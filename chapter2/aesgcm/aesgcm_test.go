package aesgcm

import (
	"bytes"
	"testing"
)

var testCT []byte

func TestBasicEncrypt(t *testing.T) {
	k := make([]byte, KeySize)
	message := []byte("AAAA")
	ct, ok := Encrypt(k, message)
	if ct == nil || !ok {
		t.Fatal("Failed to encrypt message.")
	}
	testCT = ct
}

func TestBasicDecrypt(t *testing.T) {
	k := make([]byte, KeySize)
	message, ok := Decrypt(k, testCT)
	if message == nil || !ok {
		t.Fatal("Failed to decrypt message.")
	}

	if !bytes.Equal(message, []byte("AAAA")) {
		t.Fatalf("Invalid decryption.\n\t%v\n", message)
	}
}
