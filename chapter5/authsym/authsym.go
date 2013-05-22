package authsym

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"os"
)

const HashLen = 32
var msgNumChan chan int64

func init() {
	msgNumChan := make(chan int64, 1)

	go func() {
		var msgNum int64
		for {
			fmt.Printf("msg number: %d\n", msgNum);
			msgNumChan<-msgNum
			msgNum++
		}
	}()
}

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

	fmt.Println("get msgno")
	msgno := <-msgNumChan
	fmt.Println("prepend msgno")
	msgnum := []byte(fmt.Sprintf("%0d", msgno))
	pt = append(msgnum, pt...)
	fmt.Println("encrypt")
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
		Scrub(pt, 3)
		pt = []byte{}
	} else {
		pt = pt[8:]
	}
	return
}

// Random returns a byte slice containing size random bytes.
func Random(size int) (b []byte, err error) {
	b = make([]byte, size)
	_, err = io.ReadFull(rand.Reader, b)
	return
}

// GenerateKey returns a key suitable for AES-256 cryptography.
func GenerateKey() (key []byte, err error) {
	return Random(KeySize)
}

// Generates a long-term (LT) key. It uses the `/dev/random`
// device, and will typically be much slower than GenerateKey.
func GenerateLTKey() (key []byte, err error) {
	devRandom, err := os.Open("/dev/random")
	if err != nil {
		return
	}
	key = make([]byte, KeySize)
	_, err = io.ReadFull(devRandom, key)
	return
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
