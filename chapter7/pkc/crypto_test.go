package pkc

import "bytes"
import "crypto/rsa"
import "fmt"
import "testing"

var (
	testkey *rsa.PrivateKey
	testct  []byte
	testmsg []byte
)

func TestGenerateKey(t *testing.T) {
	var err error

	testkey, err = GenerateKey()
	if err != nil {
		fmt.Println("failed to generate a key:", err.Error())
		t.FailNow()
	} else if err = testkey.Validate(); err != nil {
		fmt.Println("generated bad key:", err.Error())
		t.FailNow()
	}
	fmt.Println("INFO: max message length:",
		MaxMessageLength(&testkey.PublicKey))
}

func TestEncrypt(t *testing.T) {
	var err error

	testmsg = []byte("Hello, world.")
	testct, err = Encrypt(&testkey.PublicKey, testmsg)
	if err != nil {
		fmt.Println("TestEncrypt failed:", err.Error())
		t.FailNow()
	}
}

func TestDecrypt(t *testing.T) {
	decrypted, err := Decrypt(testkey, testct)
	if err != nil {
		fmt.Println("Decrypt failed:", err.Error())
		t.FailNow()
	} else if !bytes.Equal(decrypted, testmsg) {
		fmt.Println("malformed decrypted plaintext")
		t.FailNow()
	}
}
