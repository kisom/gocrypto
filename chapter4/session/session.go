// Package session contains an example implementation of a session-based
// mechanism for tracking message numbers. A session contains a key pair
// for each side of the link.
//
// There are two parties in a session: the dialer intitiates the session
// with a listener. At the start of the session, the dialer sends its
// two public keys to the listener, who responds with its own public keys.
// The first public key is used to encrypt traffic going from the dialer
// to the listener, and the second is used to encrypt traffic from the
// listener to the dialer.
package session

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"git.metacircular.net/kyle/gocrypto/chapter3/nacl"
	"git.metacircular.net/kyle/gocrypto/util"
	"golang.org/x/crypto/nacl/box"
)

// A Channel is an underlying transport channel that the session will
// be established over.
type Channel io.ReadWriter

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
	// LastSent keeps track of the message numbers for messages sent
	// from this session to the peer..
	LastSent uint64

	// sendKey is the key used to encrypt outgoing messages to
	// the peer.
	sendKey *[32]byte

	// LastRecv tracks the message numbers for messages received by
	// this session.
	LastRecv uint64

	// recvKey contains the session key used to decrypt incoming
	// messages from the peer.
	recvKey *[32]byte

	// Channel is the underlying (insecure) communications channel.
	Channel Channel
}

// Encrypt adds a message number to the session and secures it with a
// symmetric ciphersuite. The message cannot be empty.
func (s *Session) Encrypt(message []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, secret.ErrEncrypt
	}

	s.LastSent++
	m := MarshalMessage(Message{s.LastSent, message})
	return secret.Encrypt(s.sendKey, m)
}

// Send encrypts the message and sends it out over the channel.
func (s *Session) Send(message []byte) error {
	m, err := s.Encrypt(message)
	if err != nil {
		return err
	}

	err = binary.Write(s.Channel, binary.BigEndian, uint32(len(m)))
	if err != nil {
		return err
	}

	_, err = s.Channel.Write(m)
	return err
}

// Decrypt recovers the message and verifies the message number. If the
// message number hasn't incremented, it's considered a decryption
// failure.
func (s *Session) Decrypt(message []byte) ([]byte, error) {
	out, err := secret.Decrypt(s.recvKey, message)
	if err != nil {
		return nil, err
	}

	m, ok := UnmarshalMessage(out)
	if !ok {
		return nil, secret.ErrDecrypt
	}

	if m.Number <= s.LastRecv {
		return nil, secret.ErrDecrypt
	}

	s.LastRecv = m.Number

	return m.Contents, nil
}

// Receive listens for a new message on the channel.
func (s *Session) Receive() ([]byte, error) {
	var mlen uint32
	err := binary.Read(s.Channel, binary.BigEndian, &mlen)
	if err != nil {
		return nil, err
	}

	message := make([]byte, int(mlen))
	_, err = io.ReadFull(s.Channel, message)
	if err != nil {
		return nil, err
	}

	return s.Decrypt(message)
}

func generateKeyPair() (*[64]byte, *[64]byte, error) {
	pub := new([64]byte)
	priv := new([64]byte)

	recvPub, recvPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	copy(pub[:], recvPub[:])
	copy(priv[:], recvPriv[:])

	sendPub, sendPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	copy(pub[32:], sendPub[:])
	copy(priv[32:], sendPriv[:])
	return pub, priv, err
}

// Close zeroises the keys in the session.
func (s *Session) Close() error {
	util.Zero(s.sendKey[:])
	util.Zero(s.recvKey[:])
	return nil
}

// keyExchange is a convenience function that takes keys as byte slices,
// copying them into the appropriate arrays.
func keyExchange(shared *[32]byte, priv, pub []byte) {
	// Copy the private key and wipe it, as it will no longer be needed.
	var kexPriv [32]byte
	copy(kexPriv[:], priv)
	util.Zero(priv)

	var kexPub [32]byte
	copy(kexPub[:], pub)

	box.Precompute(shared, &kexPub, &kexPriv)
	util.Zero(kexPriv[:])
}

// Dial sets up a new session over the channel by generating a new pair
// of Curve25519 keypairs, sending its public keys to the peer, and
// reading the peer's public keys back.
func Dial(ch Channel) (*Session, error) {
	var peer [64]byte
	pub, priv, err := generateKeyPair()
	if err != nil {
		return nil, err
	}

	_, err = ch.Write(pub[:])
	if err != nil {
		return nil, err
	}

	// Make sure the entire public key is read.
	_, err = io.ReadFull(ch, peer[:])
	if err != nil {
		return nil, err
	}

	s := &Session{
		recvKey: new([32]byte),
		sendKey: new([32]byte),
		Channel: ch,
	}

	// The first 32 bytes are the A->B link, where A is the
	// dialer. This key material should be used to set up the
	// A send key.
	keyExchange(s.sendKey, priv[:32], peer[:32])

	// The last 32 bytes are the B->A link, where A is the
	// dialer. This key material should be used to set up the A
	// receive key.
	keyExchange(s.recvKey, priv[32:], peer[32:])

	return s, nil
}

// Listen waits for a peer to Dial in, then sets up a key exchange
// and session.
func Listen(ch Channel) (*Session, error) {
	var peer [64]byte
	pub, priv, err := generateKeyPair()
	if err != nil {
		return nil, err
	}

	// Ensure the entire peer key is read.
	_, err = io.ReadFull(ch, peer[:])
	if err != nil {
		return nil, err
	}

	_, err = ch.Write(pub[:])
	if err != nil {
		return nil, err
	}

	s := &Session{
		recvKey: new([32]byte),
		sendKey: new([32]byte),
		Channel: ch,
	}

	// The first 32 bytes are the A->B link, where A is the
	// dialer. This key material should be used to set up the
	// B receive key.
	keyExchange(s.recvKey, priv[:32], peer[:32])

	// The last 32 bytes are the B->A link, where A is the
	// dialer. This key material should be used to set up the
	// B send key.
	keyExchange(s.sendKey, priv[32:], peer[32:])

	return s, nil
}
