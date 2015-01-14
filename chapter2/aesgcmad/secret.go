package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"git.metacircular.net/kyle/gocrypto/util"
)

const (
	KeySize   = 32
	NonceSize = 12
)

var (
	ErrEncrypt = errors.New("secret: encryption failed")
	ErrDecrypt = errors.New("secret: decryption failed")
)

var keyDB = map[uint32][]byte{}

// EncryptWithID secures a message and prepends a 4-byte sender ID
// to the message.
func EncryptWithID(key, message []byte, sender uint32) ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, sender)

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrEncrypt
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, ErrEncrypt
	}

	nonce, err := util.RandBytes(NonceSize)
	if err != nil {
		return nil, ErrEncrypt
	}

	buf = append(buf, nonce...)
	buf = gcm.Seal(buf, nonce, message, buf[:4])
	return buf, nil
}

// DecryptWithID takes an incoming message and uses the sender ID to
// retrieve the appropriate key. It then attempts to recover the message
// using that key.
func DecryptWithID(message []byte) ([]byte, error) {
	if len(message) <= NonceSize+4 {
		return nil, ErrDecrypt
	}

	id := binary.BigEndian.Uint32(message[:4])
	key, ok := SelectKeyForID(id)
	if !ok {
		return nil, ErrDecrypt
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecrypt
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, ErrDecrypt
	}

	nonce := make([]byte, NonceSize)
	copy(nonce, message[4:])

	// Decrypt the message, using the sender ID as the additional
	// data requiring authentication.
	out, err := gcm.Open(nil, nonce, message[4+NonceSize:], message[:4])
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

// SelectKeyForID is a mock call into a key database.
func SelectKeyForID(id uint32) ([]byte, bool) {
	k, ok := keyDB[id]
	return k, ok
}
