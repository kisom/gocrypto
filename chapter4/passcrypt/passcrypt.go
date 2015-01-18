package passcrypt

import (
	"errors"
	"log"

	"git.metacircular.net/kyle/gocrypto/chapter3/nacl"
	"git.metacircular.net/kyle/gocrypto/util"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const SaltSize = 32

var (
	// ErrEncrypt is returned when encryption fails.
	ErrEncrypt = errors.New("secret: encryption failed")

	// ErrDecrypt is returned when decryption fails.
	ErrDecrypt = errors.New("secret: decryption failed")
)

// deriveKey generates a new NaCl key from a passphrase and salt.
func deriveKey(pass, salt []byte) (*[secret.KeySize]byte, error) {
	var naclKey = new([secret.KeySize]byte)
	key, err := scrypt.Key(pass, salt, 1048576, 8, 1, secret.KeySize)
	if err != nil {
		return nil, err
	}

	copy(naclKey[:], key)
	util.Zero(key)
	return naclKey, nil
}

// Encrypt secures a message using a passphrase.
func Encrypt(pass, message []byte) ([]byte, error) {
	salt, err := util.RandBytes(SaltSize)
	if err != nil {
		return nil, ErrEncrypt
	}

	key, err := deriveKey(pass, salt)
	if err != nil {
		return nil, ErrEncrypt
	}

	out, err := secret.Encrypt(key, message)
	util.Zero(key[:]) // Zero key immediately after
	if err != nil {
		return nil, ErrEncrypt
	}

	out = append(salt, out...)
	return out, nil
}

const Overhead = SaltSize + secretbox.Overhead + secret.NonceSize

// Decrypt recovers a message encrypted using a passphrase.
func Decrypt(pass, message []byte) ([]byte, error) {
	if len(message) < Overhead {
		log.Print("length")
		return nil, ErrDecrypt
	}

	key, err := deriveKey(pass, message[:SaltSize])
	if err != nil {
		log.Print("scrypt")
		return nil, ErrDecrypt
	}

	out, err := secret.Decrypt(key, message[SaltSize:])
	util.Zero(key[:]) // Zero key immediately after
	if err != nil {
		log.Printf("decrypt")
		return nil, ErrDecrypt
	}

	return out, nil
}
