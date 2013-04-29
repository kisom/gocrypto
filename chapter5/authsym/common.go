package authsym

import (
        "crypto/rand"
        "crypto/cipher"
        "crypto/aes"
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
	return Random(aes.BlockSize)
}

func encrypt(key, ct []byte) (pt []byte, err error) {
        buf := ct[:]
        aes, err := aes.NewCipher(key)
        if err != nil {
                return
        }

        pt, err = GenerateIV()
        if err != nil {
                return
        }

        ctr := cipher.NewCTR(aes, pt)
        ctr.XORKeyStream(buf, buf)
        pt = append(pt, buf...)
        return
}

func decrypt(key, pt []byte) (ct []byte, err error) {
        iv := pt[:BlockSize]
        ct = pt[BlockSize:]
        aes, err := aes.NewCipher(key)
        if err != nil {
                return
        }

        ctr := cipher.NewCTR(aes, iv)
        ctr.XORKeyStream(ct, ct)
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
