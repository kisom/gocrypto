package echybrid

import (
	"bytes"
	"fmt"
	"github.com/kisom/gocrypto/chapter9/ecies"
	"io/ioutil"
	"testing"
)

var (
	testSender   *ecies.PrivateKey
	testReceiver *ecies.PrivateKey
	testct       []byte
	testmsg      []byte
)

func TestKeyGeneration(t *testing.T) {
	var err error
	if testSender, err = GenerateKey(); err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
	if testReceiver, err = GenerateKey(); err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if testmsg, err = ioutil.ReadFile("README"); err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
}

func TestEncrypt(t *testing.T) {
	var err error

	if testct, err = Encrypt(&testReceiver.PublicKey, testmsg); err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
}

func TestDecrypt(t *testing.T) {
	if message, err := Decrypt(testReceiver, testct); err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	} else if !bytes.Equal(message, testmsg) {
		fmt.Println("echybrid: invalid decrypted message")
		t.FailNow()
	}
}

func BenchmarkEncryption(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ct, err := Encrypt(&testReceiver.PublicKey, testmsg)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
		pt, err := Decrypt(testReceiver, ct)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		} else if !bytes.Equal(pt, testmsg) {
			fmt.Println("dhhybrid: key exchange failure")
			b.FailNow()
		}
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateKey(); err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
	}
}
