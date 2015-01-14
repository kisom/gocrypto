package secret

import (
	"bytes"
	"encoding/binary"
	"testing"

	"git.metacircular.net/kyle/gocrypto/util"
)

var (
	testMessage = []byte("Do not go gentle into that good night.")
	testKey     []byte
)

func TestSetupDB(t *testing.T) {
	var err error
	testKey, err = util.RandBytes(KeySize)
	if err != nil {
		t.Fatalf("%v", err)
	}

	keyDB[42] = testKey
	keyDB[43] = testKey
}

func TestEncryptWithID(t *testing.T) {
	ct, err := EncryptWithID(testKey, testMessage, 42)
	if err != nil {
		t.Fatalf("%v", err)
	}

	out, err := DecryptWithID(ct)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(out, testMessage) {
		t.Fatal("messages don't match")
	}

	newSender := make([]byte, 4)
	binary.BigEndian.PutUint32(newSender, 43)
	for i := 0; i < 4; i++ {
		ct[i] = newSender[i]
	}

	_, err = DecryptWithID(ct)
	if err == nil {
		t.Fatal("decryption should fail with invalid AD")
	}
}
