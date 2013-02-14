// Common cryptographic functions for the example code in chapter
// 2. These functions provide basic symmetric cryptographic tools to
// build bigger things on.
package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type Encrypted struct {
	Ciphertext []byte
	IV         []byte
}

// Generate a symmetric key.
func GenerateSymmetricKey() (key []byte, err error) {
	key = make([]byte, KeySize)

	if len(key) != KeySize {
		err = fmt.Errorf("invalid key size")
		return
	}
	n, err := io.ReadFull(rand.Reader, key)
	if err == nil && n != KeySize {
		err = fmt.Errorf("[key] invalid random read size %d", n)
	}
	return
}

// Generate a suitable initialisation vector.
func GenerateIV() (iv []byte, err error) {
	iv = make([]byte, BlockSize)
	n, err := rand.Read(iv)
	if err == nil && n != BlockSize {
		err = fmt.Errorf("[iv] invalid random read size %d", n)
	}
	return
}

// Encrypt a byte slice.
func Encrypt(key, data []byte) (e *Encrypted, err error) {
	m, err := Pad(data)
	if err != nil {
		return
	}

	e = new(Encrypted)
	e.IV, err = GenerateIV()
	if err != nil {
		return
	}

	e.Ciphertext = make([]byte, len(m))
	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	cbc := cipher.NewCBCEncrypter(c, e.IV)
	cbc.CryptBlocks(e.Ciphertext, m)
	return
}

// Decrypt ciphertext.
func Decrypt(key []byte, e *Encrypted) (m []byte, err error) {
	m = make([]byte, len(e.Ciphertext))
	pt := make([]byte, len(e.Ciphertext))

	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	cbc := cipher.NewCBCDecrypter(c, e.IV)
	cbc.CryptBlocks(pt, e.Ciphertext)

	m, err = Unpad(pt)
	return
}

// Implement the standard padding scheme for block ciphers. This
// scheme uses 0x80 as the first non-NULL padding byte, and 0x00 to
// pad out the data to a multiple of the block length as required.  If
// the message is a multiple of the block size, add a full block of
// padding. Note that the message is copied
func Pad(m []byte) (p []byte, err error) {
	mLen := len(m)

	p = make([]byte, mLen)
	copy(p, m)

	if len(p) != mLen {
		err = PaddingError
		return
	}

	padding := BlockSize - mLen % BlockSize

	p = append(p, 0x80)
	for i := 1; i < padding; i++ {
		p = append(p, 0x0)
	}
	return
}

// Unpad data padded with the standard padding scheme. See the Pad
// function for a description of this scheme.
func Unpad(p []byte) (m []byte, err error) {
	var pLen int
	origLen := len(p)

	for pLen = origLen - 1; pLen >= 0; pLen-- {
		if p[pLen] == 0x80 {
			break
		}

		if p[pLen] != 0x0 {
			break
		}

		if (p[pLen] != 0x0 && p[pLen] != 0x80) ||
			((origLen - pLen) > BlockSize) {
			err = PaddingError
			return
		}
	}

	m = make([]byte, pLen)
	copy(m, p)
	return
}

func EncryptOut(key, r io.Reader, w io.Writer) (err error) {
	return
}

// Zeroise wipes out the data in a slice before deleting the array.
func Zeroise(data []byte) (n int) {
	dLen := len(data)

	for n = 0; n < dLen; n++ {
		data[n] = 0x0
	}

	data = []byte{}
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
	if dLen != Zeroise(data) {
		err = fmt.Errorf("zeroise failed")
	}
	return
}
