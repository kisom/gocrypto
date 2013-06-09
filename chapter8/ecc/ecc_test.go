package ecc

import (
	"crypto/ecdsa"
	"fmt"
	"testing"
)

var (
	testkey *ecdsa.PrivateKey
	testmsg []byte
	testsig []byte
)

func TestGenerateKey(t *testing.T) {
	var err error
	testkey, err = GenerateKey()
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
}

func TestSign(t *testing.T) {
	testmsg = []byte("Hello, world.")
	var err error
	testsig, err = Sign(testkey, testmsg)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
}

func TestVerify(t *testing.T) {
	if !Verify(&testkey.PublicKey, testmsg, testsig) {
		fmt.Println("ecdsa: signature verification failed")
		t.FailNow()
	}
}
