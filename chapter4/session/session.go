// Package session contains an example implementation of a session-based
// mechanism for tracking message numbers.
package session

import (
	"encoding/binary"
	"log"

	"git.metacircular.net/kyle/gocrypto/chapter3/nacl"
	"golang.org/x/crypto/nacl/box"
)

// A message is considered as the pairing of a message number and some
// message contents.
type Message struct {
	Number   uint64
	Contents []byte
}

// MarshalMessage serialises a message into a byte slice. Serialising
// the message appends the contents to the 8-byte message number. The
// out variable is initialised with only eight bytes, but with a capacity
// that accounts for the message contents.
func MarshalMessage(m Message) []byte {
	out := make([]byte, 8, len(m.Contents)+8)
	binary.BigEndian.PutUint64(out[:8], m.Number)
	return append(out, m.Contents...)
}

// UnmarshalMessage parses a message from a byte slice. Unmarshaling a
// message first checks the assumption that the message contains a
// sequence number and at least one byte of contents. Then, the message
// number and contents are extracted.
func UnmarshalMessage(in []byte) (Message, bool) {
	m := Message{}
	if len(in) <= 8 {
		return m, false
	}

	m.Number = binary.BigEndian.Uint64(in[:8])
	m.Contents = in[8:]
	return m, true
}

// A Session tracks message numbers for a session. Including message
// numbers is only useful if they're being checked. We'll keep track of
// message numbers for a given session
type Session struct {
	LastSent uint64
	LastRecv uint64
	Key      *[32]byte
}

// Encrypt adds a message number to the session and secures it with a
// symmetric ciphersuite.
func (s *Session) Encrypt(message []byte) ([]byte, error) {
	s.LastSent++
	m := MarshalMessage(Message{s.LastSent, message})
	return secret.Encrypt(s.Key, m)
}

// Decrypt recovers the message and verifies the message number. If the
// message number hasn't incremented, it's considered a decryption
// failure.
func (s *Session) Decrypt(message []byte) ([]byte, error) {
	out, err := secret.Decrypt(s.Key, message)
	if err != nil {
		log.Print("decrypt")
		return nil, err
	}

	m, ok := UnmarshalMessage(out)
	if !ok {
		log.Printf("unmarshal")
		return nil, secret.ErrDecrypt
	}

	if m.Number <= s.LastRecv {
		return nil, secret.ErrDecrypt
	}

	s.LastRecv = m.Number

	return m.Contents, nil
}

// NewSession creates a new session using a NaCl key exchange.
func NewSession(priv *[32]byte, peer *[32]byte) *Session {
	s := &Session{
		Key: new([32]byte),
	}
	box.Precompute(s.Key, peer, priv)
	return s
}
