package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"errors"

	"git.metacircular.net/kyle/gocrypto/util"
)

const (
	NonceSize = aes.BlockSize
	MACSize   = 48
	CKeySize  = 32 // Cipher key size - AES-256
	MKeySize  = 48 // HMAC key size - HMAC-SHA-384
)

var KeySize = CKeySize + MKeySize

var (
	ErrEncrypt = errors.New("secret: encryption failed")
	ErrDecrypt = errors.New("secret: decryption failed")
)

// GenerateKey generates a new AES-256 and HMAC-SHA-384 key.
func GenerateKey() ([]byte, error) {
	return util.RandBytes(KeySize)
}

// GenerateNonce generates a new AES-CTR nonce.
func GenerateNonce() ([]byte, error) {
	return util.RandBytes(NonceSize)
}

// Encrypt secures a message using AES-CBC-HMAC-SHA384 with a random
// nonce.
func Encrypt(key, message []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrEncrypt
	}

	iv, err := util.RandBytes(NonceSize)
	if err != nil {
		return nil, ErrEncrypt
	}

	pmessage := pad(message)
	ct := make([]byte, len(pmessage))

	// NewCipher only returns an error with an invalid key size,
	// but the key size was checked at the beginning of the function.
	c, _ := aes.NewCipher(key[:CKeySize])
	ctr := cipher.NewCBCEncrypter(c, iv)
	ctr.CryptBlocks(ct, pmessage)

	h := hmac.New(sha512.New384, key[CKeySize:])
	ct = append(iv, ct...)
	h.Write(ct)
	ct = h.Sum(ct)
	return ct, nil
}

// Decrypt recovers a message using AES-CBC-HMAC-SHA384 with a random
// nonce.
func Decrypt(key, message []byte) ([]byte, error) {
	// HMAC-SHA-384 returns a MAC that is also a multiple of the
	// block size.
	if (len(message) % aes.BlockSize) != 0 {
		return nil, ErrDecrypt
	}

	// A message must have at least an IV block, a message block,
	// and three blocks of HMAC.
	if len(message) < (5 * aes.BlockSize) {
		return nil, ErrDecrypt
	}

	macStart := len(message) - MACSize
	tag := message[macStart:]
	out := make([]byte, macStart-NonceSize)
	message = message[:macStart]

	h := hmac.New(sha512.New384, key[CKeySize:])
	h.Write(message)
	mac := h.Sum(nil)
	if !hmac.Equal(mac, tag) {
		return nil, ErrDecrypt
	}

	// NewCipher only returns an error with an invalid key size,
	// but the key size was checked at the beginning of the function.
	c, _ := aes.NewCipher(key[:CKeySize])
	ctr := cipher.NewCBCDecrypter(c, message[:NonceSize])
	ctr.CryptBlocks(out, message[NonceSize:])

	pt := unpad(out)
	if pt == nil {
		return nil, ErrDecrypt
	}

	return pt, nil
}
