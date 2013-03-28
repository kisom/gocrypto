package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

var (
	ErrBadKey        = fmt.Errorf("invalid key")
	ErrPadding       = fmt.Errorf("invalid padding")
	ErrRandomFailure = fmt.Errorf("failed to read enough random data")
)

var (
	devRandom   *os.File
	SecureLevel = 0
)

func init() {
	var err error

	devRandom, err = os.Open("/dev/random")
	if err != nil {
		fmt.Fprintf(os.Stderr, "*** failed to open /dev/random")
		fmt.Fprintf(os.Stderr, "    long-term key generation not recommended")
	} else {
		SecureLevel = 1
	}
}

// Random returns a byte slice containing size random bytes.
func Random(size int) (b []byte, err error) {
	b = make([]byte, size)
	n, err := rand.Read(b)
	if err != nil {
		return
	} else if size != n {
		err = ErrRandomFailure
	}
	return
}

// GenerateKey returns a key suitable for AES-256 cryptography.
func GenerateKey() (key []byte, err error) {
	return Random(KeySize)
}

// Generates a long-term (LT) key. It uses the `/dev/random`
// device, and will typically be much slower than GenerateKey.
func GenerateLTKey() (key []byte, err error) {
	if devRandom == nil {
		err = DegradedError
		return
	}
	key = make([]byte, KeySize)

	n, err := io.ReadFull(devRandom, key)
	if err == nil && n != KeySize {
		err = fmt.Errorf("[key] invalid random read size %d", n)
	}
	return
}

// GenerateIV returns an initialisation vector suitable for
// AES-CBC encryption.
func GenerateIV() (iv []byte, err error) {
	return Random(aes.BlockSize)
}

// Implement the standard padding scheme for block ciphers.
func PadBuffer(m []byte) (p []byte, err error) {
	mLen := len(m)

	p = make([]byte, mLen)
	copy(p, m)

	if len(p) != mLen {
		return p, ErrPadding
	}

	padding := aes.BlockSize - mLen%aes.BlockSize

	p = append(p, 0x80)
	for i := 1; i < padding; i++ {
		p = append(p, 0x0)
	}
	return
}

// Unpad data padded with the standard padding scheme.
func UnpadBuffer(p []byte) (m []byte, err error) {
	m = p
	var pLen int
	origLen := len(m)

	for pLen = origLen - 1; pLen >= 0; pLen-- {
		if m[pLen] == 0x80 {
			break
		}

		if m[pLen] != 0x0 || (origLen-pLen) > aes.BlockSize {
			err = ErrPadding
			return
		}
	}
	m = m[:pLen]
	return
}

// Encrypt encrypts a message, prepending the IV to the beginning.
func Encrypt(key []byte, msg []byte) (ct []byte, err error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	iv, err := GenerateIV()
	if err != nil {
		return
	}

	padded, err := PadBuffer(msg)
	if err != nil {
		return
	}

	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(padded, padded) // encrypt in-place
	ct = iv
	ct = append(ct, padded...)

	return
}

var ErrInvalidIV = fmt.Errorf("invalid IV")

// Decrypt takes an encrypted messages and decrypts it.
func Decrypt(key []byte, ct []byte) (msg []byte, err error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

        // Copy the ciphertext to prevent it from being modified.
        tmp_ct := make([]byte, len(ct))
        copy(tmp_ct, ct)
	iv := tmp_ct[:aes.BlockSize]
	if len(iv) != aes.BlockSize {
		return msg, ErrInvalidIV
	}
	msg = tmp_ct[aes.BlockSize:]

	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(msg, msg)
	msg, err = UnpadBuffer(msg)
	return
}

// Read a key from a file
func ReadKeyFromFile(filename string) (key []byte, err error) {
	key, err = ioutil.ReadFile(filename)
	if err != nil {
		return
	} else if len(key) != KeySize {
		err = ErrBadKey
	}
	return
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

// Scrub writes random data to the variable the given number of
// rounds, then zeroises it.
func Scrub(data []byte, rounds int) (err error) {
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
	if dLen != Zeroise(&data) {
		err = fmt.Errorf("zeroise failed")
	}
	return
}
