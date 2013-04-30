package authsym

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

// Random returns a byte slice containing size random bytes.
func Random(size int) (b []byte, err error) {
	b = make([]byte, size)
	_, err = io.ReadFull(rand.Reader, b)
	return
}

// GenerateKey returns a key suitable for AES-256 cryptography.
func GenerateKey() (key []byte, err error) {
	return Random(KeySize)
}

// Generates a long-term (LT) key. It uses the `/dev/random`
// device, and will typically be much slower than GenerateKey.
func GenerateLTKey() (key []byte, err error) {
	devRandom, err := os.Open("/dev/random")
	if err != nil {
		return
	}
	key = make([]byte, KeySize)
	_, err = io.ReadFull(devRandom, key)
	return
}

// GenerateIV returns an initialisation vector suitable for
// AES-CBC encryption.
func GenerateIV() (iv []byte, err error) {
	return Random(BlockSize)
}

func encrypt(key, pt []byte) (ct []byte, err error) {
	buf := make([]byte, len(pt))
	copy(buf, pt)

	aes, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	ct, err = GenerateIV()
	if err != nil {
		return
	}

	ctr := cipher.NewCTR(aes, ct)
	ctr.XORKeyStream(buf, buf)
	ct = append(ct, buf...)
	return
}

func decrypt(key, ct []byte) (pt []byte, err error) {
	iv := ct[:BlockSize]
	pt = ct[BlockSize:]
	aes, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	ctr := cipher.NewCTR(aes, iv)
	ctr.XORKeyStream(pt, pt)
	return
}

// Zeroise wipes out the data in a slice before deleting the array.
func Zeroise(data *[]byte) (n int) {
	dLen := len(*data)

	for n = 0; n < dLen; n++ {
		(*data)[n] = 0x0
	}

	*data = make([]byte, 0)
	return
}

// Scrub writes random data to the variable the given number of
// rounds, then zeroises it.
func Scrub(data []byte, rounds int) (err error) {
	dLen := len(data)

	var n int
	for r := 0; r < rounds; r++ {
		for i := 0; i < dLen; i++ {
			n, err = io.ReadFull(rand.Reader, data)
			if err != nil {
				return
			} else if n != dLen {
				err = fmt.Errorf("[scrub] invalid random read size %d", n)
				return
			}
		}
	}
	if dLen != Zeroise(&data) {
		err = fmt.Errorf("zeroise failed")
	}
	return
}
