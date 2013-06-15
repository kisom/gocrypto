package dhhybrid

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/gokyle/dhkam"
	"io/ioutil"
	"testing"
)

var (
	testSender      *dhkam.PrivateKey
	testSenderKEK   *dhkam.KEK
	testReceiver    *dhkam.PrivateKey
	testReceiverKEK *dhkam.KEK
	testct          []byte
	testmsg         []byte
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

	testSenderKEK = testSender.InitializeKEK(rand.Reader,
		&testReceiver.PublicKey, dhkam.KEKAES128CBCHMACSHA256, nil, sha256.New())
	if testSenderKEK == nil {
		fmt.Println(ErrInvalidKEKParams.Error())
		t.FailNow()
	}

	testReceiverKEK = testReceiver.InitializeKEK(rand.Reader,
		&testSender.PublicKey, dhkam.KEKAES128CBCHMACSHA256, nil, sha256.New())
	if testReceiverKEK == nil {
		fmt.Println(ErrInvalidKEKParams.Error())
		t.FailNow()
	}

	if testmsg, err = ioutil.ReadFile("README"); err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
}

func TestEncrypt(t *testing.T) {
	var err error

	testct, err = Encrypt(testSender, testSenderKEK, &testReceiver.PublicKey, testmsg)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
}

func TestDecrypt(t *testing.T) {
	message, err := Decrypt(testReceiver, testReceiverKEK, &testSender.PublicKey, testct)
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
		ct, err := Encrypt(testSender, testSenderKEK, &testReceiver.PublicKey, testmsg)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
		pt, err := Decrypt(testReceiver, testReceiverKEK, &testSender.PublicKey, ct)
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
		if _, err := dhkam.GenerateKey(rand.Reader); err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
	}
}
