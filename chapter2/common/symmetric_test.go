package symmetric

import (
	"bytes"
	"fmt"
	"testing"
)

func FailWithError(t *testing.T, err error) {
	fmt.Println("failed")
	if err != nil {
		fmt.Println("[!] ", err.Error())
	}
	t.FailNow()
}

func TestGenerateSymmetricKey(t *testing.T) {
	fmt.Printf("GenerateSymmetricKey: ")
	key, err := GenerateSymmetricKey()
	if err != nil || len(key) != KeySize {
		FailWithError(t, err)
	}
	fmt.Println("ok")
}

func TestGenerateIV(t *testing.T) {
	fmt.Printf("GenerateIV: ")
	iv, err := GenerateIV()
	if err != nil || len(iv) != BlockSize {
		FailWithError(t, err)
	}
	fmt.Println("ok")
}

func TestPadBlock(t *testing.T) {
	m := []byte("Hello, world.")
	fmt.Printf("Padding a single block: ")
	p, err := Pad(m)
	if len(p) != BlockSize {
		FailWithError(t, err)
	}
	fmt.Println("ok")
}

func TestPadBlock2(t *testing.T) {
	m := []byte("ABCDABCDABCDABCD")
	fmt.Printf("Padding with full pad block: ")
	p, err := Pad(m)
	if len(p) != (2 * BlockSize) {
		FailWithError(t, err)
	}
	fmt.Println("ok")
}

func TestUnpadBlock(t *testing.T) {
	fmt.Printf("Padding: ")
	m := [][]byte{
		[]byte("Hello, world."),
		[]byte("ABCDABCDABCDABC"),
		[]byte("ABCDABCDABCDABCD"),
	}
	for i := 0; i < len(m); i++ {
		p, err := Pad(m[i])
		if err != nil {
			FailWithError(t, err)
		} else if len(p) % BlockSize != 0 {
			err = fmt.Errorf("len(p): %d", len(p))
			FailWithError(t, err)
		}

		unpad, err := Unpad(p)
		if err != nil {
			FailWithError(t, err)
		} else if !bytes.Equal(unpad, m[i]) {
			err = fmt.Errorf("unpad == '%s'", string(unpad))
			FailWithError(t, err)
		}
	}
	fmt.Println("ok")
}

func TestEncryptBlock(t *testing.T) {
	m := []byte("Hello, world.")
	fmt.Printf("Encrypt block: ")

	key, err := GenerateSymmetricKey()
	if err != nil {
		FailWithError(t, err)
	}

	e, err := Encrypt(key, m)
	if err != nil {
		FailWithError(t, err)
	}

	decrypted, err := Decrypt(key, e)
	if err != nil {
		FailWithError(t, err)
	}

	if !bytes.Equal(decrypted, m) {
		err = fmt.Errorf("plaintext doesn't match original message")
		FailWithError(t, err)
	}
	fmt.Println("ok")
}

func BenchmarkEncryptBlock(b *testing.B) {
	for i := 0; i < b.N; i++ {
		m := []byte("Hello, world.")

		key, err := GenerateSymmetricKey()
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

		Zeroise(key)
	}
}

func BenchmarkScrubKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		key, err := GenerateSymmetricKey()
		if err != nil {
			b.FailNow()
		}

		err = Scrub(key, 3)
		if err != nil {
			b.FailNow()
		}
	}
}
