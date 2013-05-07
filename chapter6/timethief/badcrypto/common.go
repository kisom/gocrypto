package badcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"math/rand"
	"time"
)

const HashLen = 32

func Hmac(key, in []byte) (hash []byte, err error) {
	h := hmac.New(sha256.New, key)
	_, err = h.Write(in)
	if err != nil {
		return
	}
	hash = h.Sum(nil)
	return
}

// CompareHash verifies the HMAC of the input.
func CompareHash(hash, key, in []byte) bool {
	matched := 0

	in_hash, err := Hmac(key, in)
	if err != nil {
		in_hash = make([]byte, len(hash))
	} else if len(hash) < len(in_hash) {
		extend := make([]byte, HashLen-len(hash))
		hash = append(hash, extend...)
	}

	for i := 0; i < HashLen; i++ {
		matched += subtle.ConstantTimeByteEq(hash[i], in_hash[i])
	}

	return matched == HashLen
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

func Encrypt(key, pt []byte) (authct []byte, err error) {
	var hash []byte

	authct, err = encrypt(key, pt)
	if err != nil {
		return
	} else if hash, err = Hmac(key, authct); err != nil {
		return
	} else {
		authct = append(authct, hash...)
	}
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

func Decrypt(key, message []byte) (pt []byte, err error) {
	hashLocation := len(message) - HashLen
	ct := message[:hashLocation]
	hash := message[hashLocation:]

	match := CompareHash(hash, key, ct)
	pt, err = decrypt(key, ct)
	if err == nil && !match {
		err = fmt.Errorf("Invalid HMAC")
		Zeroise(&pt)
		pt = []byte{}
	}
	return
}

// Random returns a byte slice containing size random bytes.
func Random(size int) (b []byte, err error) {
	seed := time.Now().Unix()
	src := rand.NewSource(seed)
	rng := rand.New(src)
	b = make([]byte, 0)
	for i := 0; i < size; i++ {
		b = append(b, byte(rng.Intn(255)))
	}
	return
}

// GenerateKey returns a key suitable for AES-256 cryptography.
func GenerateKey() (key []byte, err error) {
	return Random(KeySize)
}

// GenerateIV returns an initialisation vector suitable for
// AES-CBC encryption.
func GenerateIV() (iv []byte, err error) {
	return Random(BlockSize)
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