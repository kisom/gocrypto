package main

// crypto.go contains an implementation of AES-CBC that leaks information
// about the decryption, which can be used by an attacker to recover the
// message.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

var (
	ErrInvalidCiphertext = errors.New("oracle: invalid ciphertext")
	ErrInvalidKey        = errors.New("oracle: invalid key")
	ErrInvalidPadding    = errors.New("oracle: invalid padding")
	ErrInvalidIV         = errors.New("oracle: invalid IV")
)

// KeySize is size of AES-256-CBC keys in bytes.
const KeySize = 32

func randBytes(size int) []byte {
	p := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, p)
	if err != nil {
		p = nil
	}
	return p
}

// GenerateIV provides new IVs. The default function returns randomly
// generated IVs.
var GenerateIV = func() []byte {
	return randBytes(aes.BlockSize)
}

// NewKey randomly randomly generates a new key.
func NewKey() []byte {
	return randBytes(KeySize)
}

// Encrypt applies the necessary padding to the message and encrypts it
// with AES-CBC.
func Encrypt(k, in []byte) ([]byte, error) {
	in = Pad(in)
	iv := GenerateIV()
	if iv == nil {
		return nil, ErrInvalidIV
	}

	c, err := aes.NewCipher(k)
	if err != nil {
		return nil, ErrInvalidKey
	}

	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(in, in)
	return append(iv, in...), nil
}

// Decrypt decrypts the message and removes any padding.
func Decrypt(k, in []byte) ([]byte, error) {
	if len(in) == 0 || len(in)%aes.BlockSize != 0 {
		return nil, ErrInvalidCiphertext
	}

	c, err := aes.NewCipher(k)
	if err != nil {
		return nil, ErrInvalidKey
	}

	cbc := cipher.NewCBCDecrypter(c, in[:aes.BlockSize])
	cbc.CryptBlocks(in[aes.BlockSize:], in[aes.BlockSize:])
	out := Unpad(in[aes.BlockSize:])
	if out == nil {
		return nil, ErrInvalidPadding
	}
	return out, nil

}

// Pad applies the PKCS #7 padding scheme on the buffer.
func Pad(in []byte) []byte {
	padding := 16 - (len(in) % 16)
	if padding == 0 {
		padding = 16
	}
	for i := 0; i < padding; i++ {
		in = append(in, byte(padding))
	}
	return in
}

// Unpad strips the PKCS #7 padding on a buffer. If the padding is
// invalid, nil is returned.
func Unpad(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}

	padding := in[len(in)-1]
	if int(padding) > len(in) || padding > aes.BlockSize || padding == 0 {
		return nil
	}

	for i := len(in) - 1; i > len(in)-int(padding)-1; i-- {
		if in[i] != padding {
			return nil
		}
	}
	return in[:len(in)-int(padding)]
}
