package pkc

import "bytes"
import "crypto/rsa"
import "fmt"
import "io/ioutil"
import "os"
import "testing"

var (
	testkey *rsa.PrivateKey
	testct  []byte
	testmsg []byte
)

func tempFileName() string {
	tmpf, err := ioutil.TempFile("", "pkc-rsa_test_")
	if err != nil {
		return ""
	}
	defer tmpf.Close()
	return tmpf.Name()
}

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

func TestExportPrivateKey(t *testing.T) {
	certFile := tempFileName()
	if certFile == "" {
		fmt.Println("couldn't create a temporary file")
		t.FailNow()
	}
	defer os.Remove(certFile)

	err := ExportPrivateKey(testkey, certFile)
	if err != nil {
		fmt.Println("error exporting key:", err.Error())
		t.FailNow()
	}

	inprv, err := ImportPrivateKey(certFile)
	if err != nil {
		fmt.Println("error importing key:", err.Error())
		t.FailNow()
	} else if err = inprv.Validate(); err != nil {
		fmt.Println("imported key is invalid")
		t.FailNow()
	}
}

func TestExportPublicKey(t *testing.T) {
	certFile := tempFileName()
	if certFile == "" {
		fmt.Println("couldn't create a temporary file")
		t.FailNow()
	}
	defer os.Remove(certFile)

	err := ExportPublicKey(&testkey.PublicKey, certFile)
	if err != nil {
		fmt.Println("error exporting key:", err.Error())
		t.FailNow()
	}

	pub := &testkey.PublicKey
	inpub, err := ImportPublicKey(certFile)
	if err != nil {
		fmt.Println("error importing key:", err.Error())
		t.FailNow()
	}

	if pub.N.Cmp(inpub.N) != 0 {
		fmt.Println("imported key's modulus doesn't match")
		t.FailNow()
	} else if inpub.E != pub.E {
		fmt.Println("imported key's exponent doesn't match")
		t.FailNow()
	}
}

func TestExportPrivateKeyPEM(t *testing.T) {
	certFile := tempFileName()
	if certFile == "" {
		fmt.Println("couldn't create a temporary file")
		t.FailNow()
	}
	defer os.Remove(certFile)

	err := ExportPrivatePEM(testkey, certFile)
	if err != nil {
		fmt.Println("error exporting key:", err.Error())
		t.FailNow()
	}

	inprv, pub, err := ImportPEM(certFile)
	if err != nil {
		fmt.Println("error importing key:", err.Error())
		t.FailNow()
	} else if err = inprv.Validate(); err != nil {
		fmt.Println("imported key is invalid")
		t.FailNow()
	} else if pub != nil {
		fmt.Println("public key should not be imported")
		t.FailNow()
	}
}

func TestExportPublicKeyPEM(t *testing.T) {
	certFile := tempFileName()
	if certFile == "" {
		fmt.Println("couldn't create a temporary file")
		t.FailNow()
	}
	defer os.Remove(certFile)

	err := ExportPublicPEM(&testkey.PublicKey, certFile)
	if err != nil {
		fmt.Println("error exporting key:", err.Error())
		t.FailNow()
	}

	prv, pub, err := ImportPEM(certFile)
	if err != nil {
		fmt.Println("error importing key:", err.Error())
		t.FailNow()
	} else if prv != nil {
		fmt.Println("private key should not be imported")
		t.FailNow()
	} else if pub == nil {
		fmt.Println("public key was not imported")
		t.FailNow()
	} else if pub.E != 65537 {
		fmt.Println("bad exponent in public key")
		t.FailNow()
	}
}
