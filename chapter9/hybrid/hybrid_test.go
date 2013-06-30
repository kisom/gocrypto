package hybrid

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"github.com/kisom/gocrypto/chapter7/pkc"
	"io/ioutil"
	"testing"
)

var (
	testSender   *rsa.PrivateKey
	testReceiver *rsa.PrivateKey
	testMessage  []byte
	testct       []byte
)

func TestGenerateKeys(t *testing.T) {
	var err error

	if testSender, _, err = pkc.ImportPEM("testdata/1.key"); err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	} else if testSender == nil {
		fmt.Println("hybrid: failed to read test key")
		t.FailNow()
	}
	if testReceiver, _, err = pkc.ImportPEM("testdata/2.key"); err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	} else if testReceiver == nil {
		fmt.Println("hybrid: failed to read test key")
		t.FailNow()
	}

	if testMessage, err = ioutil.ReadFile("TEST.txt"); err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
}

func TestEncrypt(t *testing.T) {
	var err error
	testct, err = Encrypt(&testReceiver.PublicKey, testMessage)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
	ioutil.WriteFile("testct.out", testct, 0644)
}

func TestDecrypt(t *testing.T) {
	msg, err := Decrypt(testReceiver, testct)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	} else if !bytes.Equal(msg, testMessage) {
		fmt.Println("hybrid: failed to decrypt message")
		t.FailNow()
	}
}

func BenchmarkEncryption(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ct, err := Encrypt(&testReceiver.PublicKey, testMessage)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}

		msg, err := Decrypt(testReceiver, ct)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		} else if !bytes.Equal(msg, testMessage) {
			fmt.Println("hybrid: failed to decrypt message")
			b.FailNow()
		}
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := pkc.GenerateKey(); err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
	}
}
