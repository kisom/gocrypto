package dhhybrid

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/gokyle/dhkam"
	"io/ioutil"
	"testing"
)

var (
	testSender   *dhkam.PrivateKey
	testReceiver *dhkam.PrivateKey
	testct       []byte
	testmsg      []byte
)

func TestGenerateKeys(t *testing.T) {
	var err error
	if testSender, err = dhkam.GenerateKey(rand.Reader); err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if testReceiver, err = dhkam.GenerateKey(rand.Reader); err != nil {
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

	testct, err = Encrypt(testSender, &testReceiver.PublicKey, testmsg)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
}

func TestDecrypt(t *testing.T) {
	message, err := Decrypt(testReceiver, &testSender.PublicKey, testct)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	} else if !bytes.Equal(message, testmsg) {
		fmt.Println("dhhybrid: key exchange failure")
		t.FailNow()
	}
}

func BenchmarkEncryption(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ct, err := Encrypt(testSender, &testReceiver.PublicKey, testmsg)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
		pt, err := Decrypt(testReceiver, &testSender.PublicKey, ct)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		} else if !bytes.Equal(pt, testmsg) {
			fmt.Println("dhhybrid: key exchange failure")
			b.FailNow()
		}
	}
}
