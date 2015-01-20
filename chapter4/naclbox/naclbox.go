// Package naclbox encrypts data using ephemeral Curve25519 keys.
package naclbox

import (
	"crypto/rand"
	"errors"

	"git.metacircular.net/kyle/gocrypto/util"
	"golang.org/x/crypto/nacl/box"
)

var (
	// ErrEncrypt is returned when encryption fails.
	ErrEncrypt = errors.New("secret: encryption failed")

	// ErrDecrypt is returned when decryption fails.
	ErrDecrypt = errors.New("secret: decryption failed")
)

// Encrypt secures a message to the peer's public key using an ephemeral
// key pair.
func Encrypt(peer *[32]byte, message []byte) ([]byte, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ErrEncrypt
	}

	var nonce [24]byte
	nbs, err := util.RandBytes(24)
	if err != nil {
		return nil, ErrEncrypt
	}

	copy(nonce[:], nbs)
	nbs = box.Seal(nbs, message, &nonce, peer, priv)
	out := make([]byte, 32, 32+len(nbs))
	copy(out, pub[:])
	return append(out, nbs...), nil
}

// Overhead is the length of additional data that will be added to the message.
const Overhead = box.Overhead + 32 + 24

// Decrypt recovers a message secured using an ephemeral public key.
func Decrypt(priv *[32]byte, message []byte) ([]byte, error) {
	if len(message) <= Overhead {
		return nil, ErrDecrypt
	}

	var pub [32]byte
	var nonce [24]byte
	copy(pub[:], message)
	copy(nonce[:], message[32:])
	out, ok := box.Open(nil, message[56:], &nonce, &pub, priv)
	if !ok {
		return nil, ErrDecrypt
	}

	return out, nil
}
