package authsym

import (
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
)

func Hmac(key, in []byte) (hash []byte, err error) {
	h := hmac.New(sha512.New, key)
	n, err := h.Write(in)
	if err != nil {
		return
	} else if n != len(in) {
		err = fmt.Errorf("failed to compute HMAC")
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

	for i := 0; i < sha512.Size; i++ {
		matched += subtle.ConstantTimeByteEq(hash[i], in_hash[i])
	}

	return matched == sha512.Size
}

func Encrypt(key, plaintext []byte) (authct []byte, err error) {
	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		return
	}

	authct, err = Hmac(key, ciphertext)
	if err == nil {
		authct = append(authct, ciphertext...)
	}
	return
}

func Decrypt(key, ciphertext []byte) (pt []byte, err error) {
	hash := ciphertext[:sha512.Size]
	ct := ciphertext[sha512.Size:]

	pt, err = decrypt(key, ct)
	match := CompareHash(hash, key, ct)
	if err == nil && !match {
		err = fmt.Errorf("Invalid HMAC")
		Scrub(pt, 3)
		pt = []byte{}
	}
	return
}
