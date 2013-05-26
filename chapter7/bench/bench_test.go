package bench

import "fmt"
import "testing"

func TestAES(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		fmt.Println("failed to generate AES key:", err.Error())
		t.FailNow()
	}

	msg := []byte("Hello, world.")
	if err = AESEncryptDecrypt(key, msg); err != nil {
		fmt.Println("AES encryption failed:", err.Error())
		t.FailNow()
	}
}

func TestRSA(t *testing.T) {
	key, err := GenerateRSAKey()
	if err != nil {
		fmt.Println("failed to generate RSA key:", err.Error())
		t.FailNow()
	}

	msg := []byte("Hello, world.")
	err = RSAEncryptDecrypt(key, msg)
	if err != nil {
		fmt.Println("RSA encryption failed:", err.Error())
		t.FailNow()
	}
}

func BenchmarkAESKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateAESKey()
		if err != nil {
			b.Fail()
		}
	}
}

func BenchmarkRSAKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateRSAKey()
		if err != nil {
			b.Fail()
		}
	}
}

func BenchmarkPrecomputedRSAKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		k, err := GenerateRSAKey()
		if err != nil {
			b.Fail()
		} else {
			k.Precompute()
		}
	}
}

func BenchmarkAESHMACEncryption(b *testing.B) {
	msg := []byte("Hello, world")
	k, err := GenerateAESKey()
	if err != nil {
		b.Fail()
	}

	for i := 0; i < b.N; i++ {
		if err = AESEncryptDecrypt(k, msg); err != nil {
			b.Fail()
		}
	}
}

func BenchmarkRSANoPCEncryption(b *testing.B) {
	msg := []byte("Hello, world.")
	k, err := GenerateRSAKey()
	if err != nil {
		b.Fail()
	}

	for i := 0; i < b.N; i++ {
		if err = RSAEncryptDecrypt(k, msg); err != nil {
			b.Fail()
		}
	}
}

func BenchmarkRSAPCEncryption(b *testing.B) {
	msg := []byte("Hello, world.")
	k, err := GenerateRSAKey()
	if err != nil {
		b.Fail()
	}
	k.Precompute()

	for i := 0; i < b.N; i++ {
		if err = RSAEncryptDecrypt(k, msg); err != nil {
			b.Fail()
		}
	}
}
