package pkc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

const KeySize = 3072

var defaultLabel = []byte{}

func MaxMessageLength(key *rsa.PublicKey) int {
	if key == nil {
		return 0
	}
	return (key.N.BitLen() / 8) - (2 * sha256.Size) - 2
}

func GenerateKey() (key *rsa.PrivateKey, err error) {
	return rsa.GenerateKey(rand.Reader, KeySize)
}

func Encrypt(pub *rsa.PublicKey, pt []byte) (ct []byte, err error) {
	if len(ct) > MaxMessageLength(pub) {
		err = fmt.Errorf("message is too long")
		return
	}

	hash := sha256.New()
	ct, err = rsa.EncryptOAEP(hash, rand.Reader, pub, pt, defaultLabel)
	return
}

func Decrypt(prv *rsa.PrivateKey, ct []byte) (pt []byte, err error) {
	hash := sha256.New()
	pt, err = rsa.DecryptOAEP(hash, rand.Reader, prv, ct, defaultLabel)
	return
}

func ExportPrivateKey(prv *rsa.PrivateKey, filename string) (err error) {
	cert := x509.MarshalPKCS1PrivateKey(prv)
	err = ioutil.WriteFile(filename, cert, 0600)
	return
}

func ExportPublicKey(pub *rsa.PublicKey, filename string) (err error) {
	cert, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return
	}
	err = ioutil.WriteFile(filename, cert, 0644)
	return
}

func ImportPrivateKey(filename string) (prv *rsa.PrivateKey, err error) {
	cert, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	prv, err = x509.ParsePKCS1PrivateKey(cert)
	return
}

func ImportPublicKey(filename string) (pub *rsa.PublicKey, err error) {
	cert, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	in, err := x509.ParsePKIXPublicKey(cert)
	if err != nil {
		return nil, err
	}
	pub = in.(*rsa.PublicKey)
	return
}
