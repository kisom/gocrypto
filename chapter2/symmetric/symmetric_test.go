package symmetric

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

const (
	testEnc = "/tmp/test.out"
	testOut = "/tmp/test.dat"
	testRef = "testdata/vector01.dat"
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
	fmt.Printf("GenerateKey: ")
	key, err := GenerateKey()
	if err != nil || len(key) != KeySize {
		FailWithError(t, err)
	}
	fmt.Println("ok")
}

// Test long term key generation.
func TestGenerateLTKey(t *testing.T) {
	fmt.Printf("GenerateLTKey: ")
	if SecureLevel < 1 {
		err := fmt.Errorf("crypto library operating in degraded mode")
		FailWithError(t, err)
	}

	key, err := GenerateLTKey()
	if err != nil || len(key) != KeySize {
		FailWithError(t, err)
	}
	fmt.Println("ok")
}

// Test initialisation vector generation.
func TestGenerateIV(t *testing.T) {
	fmt.Printf("GenerateIV: ")
	iv, err := GenerateIV()
	if err != nil || len(iv) != BlockSize {
		FailWithError(t, err)
	}
	fmt.Println("ok")
}

// Test padding a single block.
func TestPadBlock(t *testing.T) {
	m := []byte("Hello, world.")
	fmt.Printf("Pad: ")
	p, err := Pad(m)
	if len(p) != BlockSize {
		FailWithError(t, err)
	}
	fmt.Println("ok")
}

// Test padding a longer block of data.
func TestPadBlock2(t *testing.T) {
	m := []byte("ABCDABCDABCDABCD")
	fmt.Printf("Pad/Unpad: ")
	p, err := Pad(m)
	if len(p) != (2 * BlockSize) {
		FailWithError(t, err)
	}
	fmt.Println("ok")
}

// Verify the unpadding function gives the message we started
// with. Tests a few test vectors with specific lengths to test the
// behaviour of the padding code, followed by "Hello, world." in
// several languages (as provided by Google Translate) to ensure
// unicode support.
func TestUnpadBlock(t *testing.T) {
	fmt.Printf("Padding: ")
	m := [][]byte{
		[]byte("ABCDABCDABCDABC"),
		[]byte("ABCDABCDABCDABCD"),
		[]byte("This is a much longer test message. It should still work."),
		[]byte("Hello, world."),
		[]byte("Halló, heimur."),
		[]byte("こんにちは、世界。"),
		[]byte("خوش آمدید، جهان است."),
		[]byte("Здравствуй, мир."),
	}
	for i := 0; i < len(m); i++ {
		p, err := Pad(m[i])
		if err != nil {
			FailWithError(t, err)
		} else if len(p)%BlockSize != 0 {
			err = fmt.Errorf("len(p): %d", len(p))
			FailWithError(t, err)
		}

		unpad, err := Unpad(p)
		if err != nil {
			FailWithError(t, err)
		} else if len(unpad) != len(m[i]) {
			err = fmt.Errorf("len(p): %d", len(p))
			FailWithError(t, err)
		} else if !bytes.Equal(unpad, m[i]) {
			err = fmt.Errorf("unpad == '%s'", string(unpad))
			FailWithError(t, err)
		}
	}
	fmt.Println("ok")
}

// Does D(E(k,m)) == m?
func TestEncryptDecryptBlock(t *testing.T) {
	m := []byte("Hello, world.")
	fmt.Printf("Encrypt: ")

	key, err := GenerateKey()
	if err != nil {
		FailWithError(t, err)
	}

	e, err := Encrypt(key, m)
	if err != nil {
		FailWithError(t, err)
	}

	decrypted, err := e.Decrypt(key)
	if err != nil {
		FailWithError(t, err)
	}

	if !bytes.Equal(decrypted, m) {
		err = fmt.Errorf("plaintext doesn't match original message")
		FailWithError(t, err)
	}
	fmt.Println("ok")
}

// Test Zeroise, which is used in the EncryptReader
func TestZeroise(t *testing.T) {
	fmt.Printf("Zeroise: ")

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
	fmt.Println("ok")
}

// Test the encryption of a file.
func TestEncryptReader(t *testing.T) {
	fmt.Printf("EncryptReader: ")
	const testFile = "testdata/vector01.dat"
	const testOut = "/tmp/test.out"
	var err error

	testKey, err = GenerateKey()
	if err != nil {
		FailWithError(t, err)
	}
	src, err := os.Open(testFile)
	if err != nil {
		FailWithError(t, err)
	}

	out, err := os.OpenFile(testOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		FailWithError(t, err)
	}

	err = EncryptReader(testKey, src, out)
	if err != nil {
		FailWithError(t, err)
	}
	out.Close()

	fi, err := os.Stat(testFile)
	if err != nil {
		FailWithError(t, err)
	}
	expected := (fi.Size()/BlockSize)*BlockSize + (2 * BlockSize)
	fi, err = os.Stat(testOut)
	if err != nil {
		err = fmt.Errorf("[testOut] %s", err.Error())
		FailWithError(t, err)
	}

	if expected != fi.Size() {
		err = fmt.Errorf("output file is the wrong size (%d instead of %d)",
			fi.Size(), expected)
	}
	if err != nil {
		FailWithError(t, err)
	}

	fmt.Println("ok")
}

// Test the encryption of a file.
func TestDecryptReader(t *testing.T) {
	fmt.Printf("DecryptReader: ")

	src, err := os.Open(testEnc)
	if err != nil {
		FailWithError(t, err)
	}

	out, err := os.OpenFile(testOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		FailWithError(t, err)
	}

	err = DecryptReader(testKey, src, out)
	if err != nil {
		FailWithError(t, err)
	}
	out.Close()

	fi, err := os.Stat(testRef)
	if err != nil {
		FailWithError(t, err)
	}
	expected := fi.Size()
	fi, err = os.Stat(testOut)
	if err != nil {
		err = fmt.Errorf("[testOut] %s", err.Error())
		FailWithError(t, err)
	}

	if expected != fi.Size() {
		err = fmt.Errorf("output file is the wrong size (%d instead of %d)",
			fi.Size(), expected)
	}

	os.Remove(testEnc)
	os.Remove(testOut)
	if err != nil {
		FailWithError(t, err)
	}

	fmt.Println("ok")
}

// Test the encryption of a file.
func TestEncryptFile(t *testing.T) {
	fmt.Printf("EncryptFile: ")
	var err error

	err = EncryptFile(testRef, testEnc, testKey)
	if err != nil {
		FailWithError(t, err)
	}

	fi, err := os.Stat(testRef)
	if err != nil {
		FailWithError(t, err)
	}

	expected := (fi.Size()/BlockSize)*BlockSize + (2 * BlockSize)
	fi, err = os.Stat(testEnc)
	if err != nil {
		err = fmt.Errorf("[testEnc] %s", err.Error())
		FailWithError(t, err)
	}

	if expected != fi.Size() {
		err = fmt.Errorf("output file is the wrong size (%d instead of %d)",
			fi.Size(), expected)
	}
	if err != nil {
		FailWithError(t, err)
	}

	fmt.Println("ok")
}

// Test the encryption of a file.
func TestDecryptFile(t *testing.T) {
	fmt.Printf("DecryptFile: ")

	err := DecryptFile(testEnc, testOut, testKey)
	if err != nil {
		FailWithError(t, err)
	}

	fi, err := os.Stat(testRef)
	if err != nil {
		FailWithError(t, err)
	}
	expected := fi.Size()
	fi, err = os.Stat(testOut)
	if err != nil {
		err = fmt.Errorf("[testOut] %s", err.Error())
		FailWithError(t, err)
	}

	if expected != fi.Size() {
		err = fmt.Errorf("output file is the wrong size (%d instead of %d)",
			fi.Size(), expected)
                panic(err.Error())
	}

	os.Remove(testEnc)
	os.Remove(testOut)
	if err != nil {
		FailWithError(t, err)
	}

	fmt.Println("ok")
}

// Test to/from byte functions.
func TestByteCrypt(t *testing.T) {
	msg := []byte("Hello, world. Hallo, welt.")

	fmt.Printf("ByteCrypt: ")
	e, err := Encrypt(testKey, msg)
	if err != nil {
		FailWithError(t, err)
	}
	enc := e.ToBytes()

	dec, err := FromBytes(enc).Decrypt(testKey)
	if err != nil {
		FailWithError(t, err)
	} else if !bytes.Equal(dec, msg) {
		FailWithError(t, nil)
	}
	fmt.Println("ok")
}

func TestByteCrypt2(t *testing.T) {
	msg := []byte("Hello, world. Hallo, welt.")

	fmt.Printf("CryptBytes: ")
	enc, err := EncryptBytes(testKey, msg)
	if err != nil {
		FailWithError(t, err)
	}

	dec, err := DecryptBytes(testKey, enc)
	if err != nil {
		FailWithError(t, err)
	}

	if !bytes.Equal(msg, dec) {
		err = fmt.Errorf("decryption failed")
		FailWithError(t, err)
	}
	fmt.Println("ok")
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

		decrypted, err := e.Decrypt(key)
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
	msg := []byte("Hello, world. Hallo, welt.")

	for i := 0; i < b.N; i++ {
		enc, err := EncryptBytes(testKey, msg)
		if err != nil {
			b.FailNow()
		}

		dec, err := DecryptBytes(testKey, enc)
		if err != nil {
			b.FailNow()
		}

		if !bytes.Equal(msg, dec) {
			b.FailNow()
		}
	}
}
