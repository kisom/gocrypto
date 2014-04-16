package secretbox

import (
	"bytes"
	"testing"
)

var testCT []byte
var testKey *[KeySize]byte

func TestBasicEncrypt(t *testing.T) {
	testKey = NewKey()
	message := []byte("AAAA")
	ct, ok := Encrypt(testKey, message)
	if ct == nil || !ok {
		t.Fatal("Failed to encrypt message.")
	}
	testCT = ct
}

func TestBasicDecrypt(t *testing.T) {
	message, ok := Decrypt(testKey, testCT)
	if message == nil || !ok {
		t.Fatal("Failed to decrypt message.")
	}

	if !bytes.Equal(message, []byte("AAAA")) {
		t.Fatalf("Invalid decryption.\n\t%v\n", message)
	}
}
