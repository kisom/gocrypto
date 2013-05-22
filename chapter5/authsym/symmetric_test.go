package authsym

import (
	"bytes"
	"fmt"
	"testing"
)

const (
	testEnc = "/tmp/test.out"
	testOut = "/tmp/test.dat"
	testRef = "testdata/vector01.dat"
	rPadRef = "testdata/vector02.dat"
)

var (
	testKey []byte
)

// FailWithError is a utility for dumping errors and failing the test.
func FailWithError(t *testing.T, err error) {
	fmt.Println("failed")
	if err != nil {
		fmt.Println("[!] ", err.Error())
	}
	t.FailNow()
}

// Test session key generation.
func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil || len(key) != KeySize {
		FailWithError(t, err)
	}
}

// Test long term key generation.
/*
func TestGenerateLTKey(t *testing.T) {
	key, err := GenerateLTKey()
	if err != nil || len(key) != KeySize {
		FailWithError(t, err)
	}
}
 */

// Test initialisation vector generation.
func TestGenerateIV(t *testing.T) {
	iv, err := GenerateIV()
	if err != nil || len(iv) != BlockSize {
		FailWithError(t, err)
	}
}

// Does D(E(k,m)) == m?
func TestEncryptDecryptBlock(t *testing.T) {
	fmt.Println("encrypt block")
	m := []byte("Hello, world.")
	key, err := GenerateKey()
	if err != nil {
		FailWithError(t, err)
	}

	fmt.Println("\tencrypt")
	e, err := Encrypt(key, m)
	if err != nil {
		FailWithError(t, err)
	}

	fmt.Println("\tdecrypt")
	decrypted, err := Decrypt(key, e)
	if err != nil {
		FailWithError(t, err)
	}

	if !bytes.Equal(decrypted, m) {
		err = fmt.Errorf("plaintext doesn't match original message")
		FailWithError(t, err)
	}
	fmt.Println("finish encrypt block")
}

func TestEncryptDecryptBlockFails(t *testing.T) {
	m := []byte("Hello, world.")

	key, err := GenerateKey()
	if err != nil {
		FailWithError(t, err)
	}

	e, err := Encrypt(key, m)
	if err != nil {
		FailWithError(t, err)
	}

	n := len(e) - 2
	orig := e[n]
	if e[n] == 255 {
		e[n] = 0
	} else {
		e[n]++
	}
	if e[n] == orig {
		err = fmt.Errorf("byte not modified")
		FailWithError(t, err)
	}
	decrypted, err := Decrypt(key, e)
	if err == nil {
		err = fmt.Errorf("HMAC should have failed")
		FailWithError(t, err)
	}

	if bytes.Equal(decrypted, m) {
		err = fmt.Errorf("decryption should not have succeeded")
		FailWithError(t, err)
	}
}

// Test Zeroise, which is used in the EncryptReader
func TestZeroise(t *testing.T) {
	var err error
	var testVector = []byte("hello, world")

	if len(testVector) != len("hello, world") {
		err = fmt.Errorf("testVector improperly initialised")
		FailWithError(t, err)
	}

	Zeroise(&testVector)
	if len(testVector) != 0 {
		err = fmt.Errorf("testVector not empty after Zeroise")
		FailWithError(t, err)
	}
}

// Benchmark the generation of session keys.
func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		key, err := GenerateKey()
		if err != nil || len(key) != KeySize {
			b.FailNow()
		}
		Zeroise(&key)
	}
}

// Benchmark the generation of long-term encryption keys.
func BenchmarkGenerateLTKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		key, err := GenerateLTKey()
		if err != nil || len(key) != KeySize {
			b.FailNow()
		}
		Zeroise(&key)
	}
}

// Benchmark the generation of initialisation vectors.
func BenchmarkGenerateIV(b *testing.B) {
	for i := 0; i < b.N; i++ {
		iv, err := GenerateIV()
		if err != nil || len(iv) != BlockSize {
			b.FailNow()
		}
		Zeroise(&iv)
	}
}

// Benchmark the encryption and decryption of a single block.
func BenchmarkEncryptBlock(b *testing.B) {
	for i := 0; i < b.N; i++ {
		m := []byte("Hello, world.")

		key, err := GenerateKey()
		if err != nil {
			fmt.Println("symkey")
			fmt.Println(err.Error())
			b.FailNow()
		}

		e, err := Encrypt(key, m)
		if err != nil {
			fmt.Println("encrypt")
			b.FailNow()
		}

		decrypted, err := Decrypt(key, e)
		if err != nil {
			fmt.Println("decrypt")
			b.FailNow()
		}

		if !bytes.Equal(decrypted, m) {
			fmt.Println("equal")
			b.FailNow()
		}

		Zeroise(&key)
	}
}

// Benchmark the scrubbing of a key.
func BenchmarkScrubKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		key, err := GenerateKey()
		if err != nil {
			b.FailNow()
		}

		err = Scrub(key, 3)
		if err != nil {
			b.FailNow()
		}
	}
}

// Benchmark encrypting and decrypting to bytes.
func BenchmarkByteCrypt(b *testing.B) {
	msg := []byte("Hello, world. Hallo, welt. Hej, världen.")

	for i := 0; i < b.N; i++ {
		enc, err := Encrypt(testKey, msg)
		if err != nil {
			b.FailNow()
		}

		dec, err := Decrypt(testKey, enc)
		if err != nil {
			b.FailNow()
		}

		if !bytes.Equal(msg, dec) {
			b.FailNow()
		}
	}
}
