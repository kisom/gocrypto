package hybrid

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
)

const HashLen = sha256.Size

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

func symEncrypt(symkey, mackey, pt []byte) (authct []byte, err error) {
	var hash []byte

	authct, err = encrypt(symkey, pt)
	if err != nil {
		return
	} else if hash, err = Hmac(mackey, authct); err != nil {
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

func symDecrypt(symkey, mackey, message []byte) (pt []byte, err error) {
	hashLocation := len(message) - HashLen
	ct := message[:hashLocation]
	hash := message[hashLocation:]

	match := CompareHash(hash, mackey, ct)
	pt, err = decrypt(symkey, ct)
	if err == nil && !match {
		err = fmt.Errorf("Invalid HMAC")
		scrub(pt, 3)
		pt = []byte{}
	}
	return
}

// Random returns a byte slice containing size random bytes.
func Random(size int) (b []byte, err error) {
	b = make([]byte, size)
	_, err = io.ReadFull(rand.Reader, b)
	return
}

// GenerateIV returns an initialisation vector suitable for
// AES-CBC encryption.
func GenerateIV() (iv []byte, err error) {
	return Random(BlockSize)
}

// Zeroise wipes out the data in a slice before deleting the array.
func zeroise(data *[]byte) (n int) {
	dLen := len(*data)

	for n = 0; n < dLen; n++ {
		(*data)[n] = 0x0
	}

	*data = make([]byte, 0)
	return
}

// Scrub writes random data to the variable the given number of
// rounds, then zeroises it.
func scrub(data []byte, rounds int) (err error) {
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
	if dLen != zeroise(&data) {
		err = fmt.Errorf("zeroise failed")
	}
	return
}
