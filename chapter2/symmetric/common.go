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
	"os"
)

type Encrypted struct {
	Ciphertext []byte
	IV         []byte
}

var (
	devRandom *os.File
	SecureLevel = 0
)

func init() {
	var err error

	devRandom, err = os.Open("/dev/random")
	if err != nil {
		fmt.Fprintf(os.Stderr, "*** failed to open /dev/random")
		fmt.Fprintf(os.Stderr, "    long-term key generation not recommended")
	} else {
		SecureLevel = 1
	}
}

// Generate a symmetric key. This is suitable for session keys
// and other short-term key material.
func GenerateKey() (key []byte, err error) {
	key = make([]byte, KeySize)

	n, err := io.ReadFull(rand.Reader, key)
	if err == nil && n != KeySize {
		err = fmt.Errorf("[key] invalid random read size %d", n)
	}
	return
}

// Generates a long-term (LT) key. It uses the `/dev/random`
// device, and will typically be much slower than GenerateKey.
func GenerateLTKey() (key []byte, err error) {
	if devRandom == nil {
		err = DegradedError
		return
	}
	key = make([]byte, KeySize)

	n, err := io.ReadFull(devRandom, key)
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
func (e *Encrypted) Decrypt(key []byte) (m []byte, err error) {
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

// ToByte converts the Encrypted struct to a byte slice, suitable, for
// example, for sending data on the network.
func (e *Encrypted) ToByte() (out []byte) {
	out = make([]byte, BlockSize)
	copy(out, e.IV)
	out = append(out, e.Ciphertext...)
	return out
}

// FromByte returns a pointer to an Encrypted struct from a byte
// slice, i.e. for messages that have come off the wire.
func FromByte(msg []byte) (e *Encrypted) {
	e = new(Encrypted)
	e.IV = make([]byte, BlockSize)
	copy(e.IV, msg)

	ct := msg[BlockSize:]
	e.Ciphertext = make([]byte, len(ct))
	copy(e.Ciphertext, ct)
	return e
}

// Implement the standard padding scheme for block ciphers. This
// scheme uses 0x80 as the first non-NULL padding byte, and 0x00 to
// pad out the data to a multiple of the block length as required.
// If the message is a multiple of the block size, add a full block
// of padding. Note that the message is copied, and the original
// isn't touched.
func Pad(m []byte) (p []byte, err error) {
	mLen := len(m)

	p = make([]byte, mLen)
	copy(p, m)

	if len(p) != mLen {
		err = PaddingError
		return
	}

	padding := BlockSize - mLen%BlockSize

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