package authsym

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
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

// CompareHash verifies the HMAC of the input. Attackers will know the
// algorithm (HMAC-SHA512) in use, so we're not worried about confirming
// that by failing on hash size mismatches.
func CompareHash(hash, key, in []byte) bool {
	matched := 0

	in_hash, err := Hmac(key, in)
	if err != nil {
		return false
	} else if len(hash) != len(in_hash) {
		return false
	}

	for i := 0; i < HashLen; i++ {
		matched += subtle.ConstantTimeByteEq(hash[i], in_hash[i])
	}

	return matched == HashLen
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

func Decrypt(key, ciphertext []byte) (pt []byte, err error) {
	hashLocation := len(ciphertext) - HashLen
	ct := ciphertext[:hashLocation]
	hash := ciphertext[hashLocation:]

	match := CompareHash(hash, key, ct)
	pt, err = decrypt(key, ct)
	if err == nil && !match {
		err = fmt.Errorf("Invalid HMAC")
		Scrub(pt, 3)
		pt = []byte{}
	}
	return
}
