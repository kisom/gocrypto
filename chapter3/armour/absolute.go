package armour

import "bytes"
import "github.com/kisom/gocrypto/chapter2/symmetric"

// Base64KeyLength is the expected length of a base64-encoded AES256 key.
const Base64KeyLength = 44

// AbsGenerateKey generates a base64-encoded key suitable for the absolute
// armoured encryption functions.
func AbsGenerateKey() (key []byte, err error) {
	rawkey, err := symmetric.GenerateKey()
	if err != nil {
		return
	}

	key = EncodeBase64(rawkey)
	return
}

func decodeKey(enckey []byte) (deckey []byte, err error) {
	deckey, err = DecodeBase64(enckey)
	if err != nil {
		return
	}
	deckey = trim(deckey)
	return
}

// Absolute Base64-encoded encryption function. The return ciphertext
// is a base64-encoded ciphertext.
func AbsEncrypt(key []byte, pt []byte) (ct []byte, err error) {
	rawkey, err := decodeKey(key)
	if err != nil {
		return
	}

	enc, err := symmetric.Encrypt(rawkey, pt)
	if err != nil {
		return
	}

	ct = trim(EncodeBase64(enc))
	return
}

// Absolute Base64-encoded decryption function. The input ciphertext
// should be base64-encoded.
func AbsDecrypt(key []byte, ct []byte) (pt []byte, err error) {
	rawkey, err := decodeKey(key)
	if err != nil {
		return
	}

	rawct, err := DecodeBase64(ct)
	if err != nil {
		return
	}
	rawct = trim(rawct)
	pt, err = symmetric.Decrypt(rawkey, rawct)
	return
}

func trim(data []byte) []byte {
	var cutset = string([]byte{0x0})
	return bytes.Trim(data, cutset)
}
