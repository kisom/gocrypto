package passcrypt

import (
	"bytes"
	"testing"
)

var (
	testMessage   = []byte("do not go gentle into that good night")
	testPassword1 = []byte("correct horse battery staple")
	testPassword2 = []byte("correct horse battery staple")
)

func TestEncryptCycle(t *testing.T) {
	out, err := Encrypt(testPassword1, testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	out, err = Decrypt(testPassword1, out)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(testMessage, out) {
		t.Fatal("recovered plaintext doesn't match original")
	}
}
