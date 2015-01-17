// Package secret provides message security using the NaCl secretbox
// ciphers.
package secret

import (
	"crypto/rand"
	"errors"
	"io"

	"code.google.com/p/go.crypto/nacl/secretbox"
)

// GenerateKey creates a new random secret key.
func GenerateKey() (*[32]byte, error) {
	key := new([32]byte)
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return nil, err
	}

	return key, nil
}

// GenerateNonce creates a new random nonce.
func GenerateNonce() (*[24]byte, error) {
	nonce := new([24]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

var (
	ErrEncrypt = errors.New("secret: encryption failed")
	ErrDecrypt = errors.New("secret: decryption failed")
)

// Encrypt generates a random nonce and encrypts the input using
// NaCl's secretbox package. The nonce is prepended to the ciphertext.
// A sealed message will the same size as the original message plus
// secretbox.Overhead bytes long.
func Encrypt(key *[32]byte, message []byte) ([]byte, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, ErrEncrypt
	}

	out := make([]byte, len(nonce))
	copy(out, nonce[:])
	out = secretbox.Seal(out, message, nonce, key)
	return out, nil
}

// Decrypt extracts the nonce from the ciphertext, and attempts to
// decrypt with NaCl's secretbox.
func Decrypt(key *[32]byte, message []byte) ([]byte, error) {
	if len(message) < (24 + secretbox.Overhead) {
		return nil, ErrDecrypt
	}

	var nonce [24]byte
	copy(nonce[:], message[:24])
	out, ok := secretbox.Open(nil, message[24:], &nonce, key)
	if !ok {
		return nil, ErrDecrypt
	}

	return out, nil
}
