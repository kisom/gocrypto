package hashsym

import (
	"bytes"
	"fmt"
	"github.com/kisom/gocrypto/chapter2/symmetric"
	"github.com/kisom/gocrypto/chapter4/hash"
)

var ErrInvalidMessage = fmt.Errorf("invalid message")

func GenerateKey() ([]byte, error) {
	return symmetric.GenerateKey()
}

func Decrypt(key []byte, ct []byte) (msg []byte, err error) {
	msg, err = symmetric.Decrypt(key, ct)
	if err != nil {
		return
	}
	h := msg[:hash.HashLen]
	msg = msg[hash.HashLen:]
	if !bytes.Equal(h, hash.New(msg).Digest()) {
		err = ErrInvalidMessage
	}
	return
}

func Encrypt(key []byte, msg []byte) (ct []byte, err error) {
	h := hash.New(msg)
	pt := h.Digest()
	pt = append(pt, msg...)
	return symmetric.Encrypt(key, pt)
}
