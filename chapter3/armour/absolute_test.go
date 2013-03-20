package armour

import (
	"bytes"
	"fmt"
	"testing"
)

func TestAbsGenerateKey(t *testing.T) {
	fmt.Printf("AbsGenerateKey: ")

	key, err := AbsGenerateKey()
	if err != nil {
		FailWithError(t, err)
	} else if len(key) != Base64KeyLength {
		FailWithError(t, fmt.Errorf("invalid encoded key length"))
	}
	fmt.Println("ok")
}

func TestAbsEncrypt(t *testing.T) {
	fmt.Printf("AbsEncryption: ")

	testMessage := []byte("Hello, gophers. This is a short test vector.")
	key, err := AbsGenerateKey()
	if err != nil {
		FailWithError(t, err)
	}

	enc, err := AbsEncrypt(key, testMessage)
	if err != nil {
		FailWithError(t, err)
	}

	dec, err := AbsDecrypt(key, enc)
	if err != nil {
		FailWithError(t, err)
	}

	if !bytes.Equal(testMessage, dec) {
		FailWithError(t, fmt.Errorf("decrypted message does not match original"))
	}
	fmt.Println("ok")
}
