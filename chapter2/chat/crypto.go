package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io/ioutil"
)

const KeySize = 16

var (
	ErrBadKey        = fmt.Errorf("invalid key")
	ErrPadding       = fmt.Errorf("invalid padding")
	ErrRandomFailure = fmt.Errorf("failed to read enough random data")
)

// Random returns a byte slice containing size random bytes.
func Random(size int) (b []byte, err error) {
	b = make([]byte, size)
	n, err := rand.Read(b)
	if err != nil {
		return
	} else if size != n {
		err = ErrRandomFailure
	}
	return
}

// GenerateKey returns a key suitable for AES-128 cryptography.
func GenerateKey() (key []byte, err error) {
	return Random(KeySize)
}

// GenerateIV returns an initialisation vector suitable for
// AES-CBC encryption.
func GenerateIV() (iv []byte, err error) {
	return Random(aes.BlockSize)
}

// Implement the standard padding scheme for block ciphers.
func PadBuffer(m []byte) (p []byte, err error) {
	mLen := len(m)

	p = make([]byte, mLen)
	copy(p, m)

	if len(p) != mLen {
		return p, ErrPadding
	}

	padding := aes.BlockSize - mLen%aes.BlockSize

	p = append(p, 0x80)
	for i := 1; i < padding; i++ {
		p = append(p, 0x0)
	}
	return
}

// Unpad data padded with the standard padding scheme.
func UnpadBuffer(p []byte) (m []byte, err error) {
	var pLen int
	origLen := len(p)

	for pLen = origLen - 1; pLen >= 0; pLen-- {
		if p[pLen] == 0x80 {
			break
		}

		if p[pLen] != 0x0 || (origLen-pLen) > aes.BlockSize {
			err = ErrPadding
			return
		}
	}

	m = make([]byte, pLen)
	copy(m, p)
	return
}

// Encrypt encrypts a message, prepending the IV to the beginning.
func Encrypt(key []byte, msg []byte) (ct []byte, err error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	iv, err := GenerateIV()
	if err != nil {
		return
	}

	padded, err := PadBuffer(msg)
	if err != nil {
		return
	}

	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(padded, padded) // encrypt in-place
	ct = iv
	ct = append(ct, padded...)

	return
}

var ErrInvalidIV = fmt.Errorf("invalid IV")

// Decrypt takes an encrypted messages and decrypts it.
func Decrypt(key []byte, ct []byte) (msg []byte, err error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	// Make sure we don't touch the original slice.
	tmp_ct := make([]byte, len(ct))
	copy(tmp_ct, ct)
	iv := tmp_ct[:aes.BlockSize]
	if len(iv) != aes.BlockSize {
		return msg, ErrInvalidIV
	}
	msg = tmp_ct[aes.BlockSize:]

	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(msg, msg)
	msg, err = UnpadBuffer(msg)
	return
}

// Read a key from a file
func ReadKeyFromFile(filename string) (key []byte, err error) {
	key, err = ioutil.ReadFile(filename)
	if err != nil {
		return
	} else if len(key) != KeySize {
		err = ErrBadKey
	}
	return
}
