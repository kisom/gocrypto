package hybrid

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"github.com/kisom/gocrypto/chapter7/pkc"
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

	if testMessage, err = ioutil.ReadFile("README"); err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
}

func TestEncrypt(t *testing.T) {
	var err error
	testct, err = Encrypt(testSender, &testReceiver.PublicKey, testMessage)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
}

func TestDecrypt(t *testing.T) {
	msg, err := Decrypt(testReceiver, &testSender.PublicKey, testct)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	} else if !bytes.Equal(msg, testMessage) {
		fmt.Println("hybrid: failed to decrypt message")
		t.FailNow()
	}
}

func BenchmarkEncryptDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ct, err := Encrypt(testSender, &testReceiver.PublicKey, testMessage)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}

		msg, err := Decrypt(testReceiver, &testSender.PublicKey, ct)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		} else if !bytes.Equal(msg, testMessage) {
			fmt.Println("hybrid: failed to decrypt message")
			b.FailNow()
		}
	}
}
