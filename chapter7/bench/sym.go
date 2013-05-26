package bench

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
)

const (
	AESKeySize = 32
	HashLen    = 32
	BlockSize  = aes.BlockSize
)

var (
	PaddingError        = fmt.Errorf("invalid padding")
	DegradedError       = fmt.Errorf("package is in degraded mode")
	BadBlockError       = fmt.Errorf("bad block")
	IVSizeMismatchError = fmt.Errorf("IV not the proper length")
	WriteError          = fmt.Errorf("write error")
)

func Hmac(key, in []byte) (hash []byte, err error) {
	h := hmac.New(sha256.New, key)
	_, err = h.Write(in)
	if err != nil {
		return
	}
	hash = h.Sum(nil)
	return
}

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

func AESEncrypt(key, pt []byte) (authct []byte, err error) {
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

func AESDecrypt(key, message []byte) (pt []byte, err error) {
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

func AESEncryptDecrypt(key, message []byte) (err error) {
	ct, err := AESEncrypt(key, message)
	if err != nil {
		return
	}

	pt, err := AESDecrypt(key, ct)
	if err != nil {
		return
	}

	if !bytes.Equal(pt, message) {
		err = fmt.Errorf("invalid plaintext")
	}
	return
}

func Random(size int) (b []byte, err error) {
	b = make([]byte, size)
	_, err = io.ReadFull(rand.Reader, b)
	return
}

func GenerateAESKey() (key []byte, err error) {
	return Random(AESKeySize)
}

func GenerateIV() (iv []byte, err error) {
	return Random(BlockSize)
}

func Zeroise(data *[]byte) (n int) {
	dLen := len(*data)

	for n = 0; n < dLen; n++ {
		(*data)[n] = 0x0
	}

	*data = make([]byte, 0)
	return
}
