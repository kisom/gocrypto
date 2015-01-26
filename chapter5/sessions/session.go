// Package session contains an example implementation of a session-based
// mechanism for tracking message numbers. A session contains a key pair
// for each side of the link, and session keys are signed by an Identity.
//
// There are two parties in a session: the dialer intitiates the session
// with a listener. At the start of the session, the dialer sends its
// two public keys to the listener, who responds with its own public keys.
// The first public key is used to encrypt traffic going from the dialer
// to the listener, and the second is used to encrypt traffic from the
// listener to the dialer.
//
// The key exchange is authenticated against a list of valid peers in
// an Identity's peer list.
package sessions

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"

	"git.metacircular.net/kyle/gocrypto/chapter3/nacl"
	"git.metacircular.net/kyle/gocrypto/util"
	"github.com/agl/ed25519"
	"github.com/kisom/sbuf"
	"golang.org/x/crypto/nacl/box"
)

// A Channel is an underlying transport channel that the session will
// be established over.
type Channel io.ReadWriter

// An Identity contains the signature keypair used for key exchanges. The
// PeerLookup provides a mechanism for verifying the identity of a peer.
type Identity struct {
	private    *[64]byte
	public     *[32]byte
	peers      []*[ed25519.PublicKeySize]byte
	PeerLookup func(*[ed25519.PublicKeySize]byte) bool
}

// NewIdentity generates a new identity.
func NewIdentity() (*Identity, error) {
	var err error
	id := &Identity{}
	id.public, id.private, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return id, nil
}

// AddPeer adds a new peer key to the Identity's peer list.
func (id *Identity) AddPeer(peerID *[ed25519.PublicKeySize]byte) {
	for i := range id.peers {
		if bytes.Equal(id.peers[i][:], peerID[:]) {
			return
		}
	}
	id.peers = append(id.peers, peerID)
}

// Public exports a copy of the Identity's public key.
func (id *Identity) Public() *[ed25519.PublicKeySize]byte {
	pub := new([ed25519.PublicKeySize]byte)
	copy(pub[:], id.public[:])
	return pub
}

// Marshal serialises a copy of the Identity. It is intended to support
// persistent Identities.
func Marshal(id *Identity) []byte {
	bufSize := ed25519.PrivateKeySize + ed25519.PublicKeySize
	bufSize += len(id.peers) * ed25519.PublicKeySize
	buf := sbuf.NewBuffer(bufSize)
	buf.Write(id.private[:])
	buf.Write(id.public[:])
	for i := range id.peers {
		buf.Write(id.peers[i][:])
	}

	return buf.Bytes()
}

// ErrInvalidIdentity is returned if the Identity being unmarshalled
// is invalid.
var ErrInvalidIdentity = errors.New("sessions: invalid identity")

// Unmarshal parses an identity.
func Unmarshal(in []byte) (*Identity, error) {
	buf := sbuf.NewBufferFrom(in)
	id := &Identity{
		private: new([ed25519.PrivateKeySize]byte),
		public:  new([ed25519.PublicKeySize]byte),
	}

	_, err := io.ReadFull(buf, id.private[:])
	if err != nil {
		return nil, ErrInvalidIdentity
	}

	_, err = io.ReadFull(buf, id.public[:])
	if err != nil {
		return nil, ErrInvalidIdentity
	}

	if (buf.Len() % ed25519.PublicKeySize) != 0 {
		return nil, ErrInvalidIdentity
	}

	for {
		if buf.Len() == 0 {
			break
		}

		peer := new([ed25519.PublicKeySize]byte)
		io.ReadFull(buf, peer[:])
		id.peers = append(id.peers, peer)
	}

	return id, nil
}

// A Message is considered as the pairing of a message number and some
// message contents.
type Message struct {
	Number   uint32
	Contents []byte
}

// MarshalMessage serialises a message into a byte slice. Serialising
// the message appends the contents to the 4-byte message number. The
// out variable is initialised with only four bytes, but with a capacity
// that accounts for the message contents.
func MarshalMessage(m Message) []byte {
	out := make([]byte, 4, len(m.Contents)+4)
	binary.BigEndian.PutUint32(out[:4], m.Number)
	return append(out, m.Contents...)
}

// UnmarshalMessage parses a message from a byte slice. Unmarshaling a
// message first checks the assumption that the message contains a
// sequence number and at least one byte of contents. Then, the message
// number and contents are extracted.
func UnmarshalMessage(in []byte) (Message, bool) {
	m := Message{}
	if len(in) <= 4 {
		return m, false
	}

	m.Number = binary.BigEndian.Uint32(in[:4])
	m.Contents = in[4:]
	return m, true
}

// A Session tracks message numbers for a session. Including message
// numbers is only useful if they're being checked. We'll keep track of
// message numbers for a given session in both directions.
type Session struct {
	// lastSent keeps track of the message numbers for messages sent
	// from this session to the peer..
	lastSent uint32

	// sendKey is the key used to encrypt outgoing messages to
	// the peer.
	sendKey *[32]byte

	// lastRecv tracks the message numbers for messages received by
	// this session.
	lastRecv uint32

	// recvKey contains the session key used to decrypt incoming
	// messages from the peer.
	recvKey *[32]byte

	// priv contains the private key, and is wiped after rekeying.
	priv *[64]byte

	// Channel is the underlying (insecure) communications channel.
	Channel Channel
}

// LastSent returns the message number of the last message to be sent
// by this session.
func (s *Session) LastSent() uint32 {
	return s.lastSent
}

// LastRecv returns the message number of the last received message.
func (s *Session) LastRecv() uint32 {
	return s.lastRecv
}

// Encrypt adds a message number to the session and secures it with a
// symmetric ciphersuite. The message cannot be empty.
func (s *Session) Encrypt(message []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, secret.ErrEncrypt
	}

	s.lastSent++
	m := MarshalMessage(Message{s.lastSent, message})
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

	if m.Number <= s.lastRecv {
		return nil, secret.ErrDecrypt
	}

	s.lastRecv = m.Number

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

// GenerateKeyPair generates a new key pair. This can be used to get a
// new key pair for setting up a rekeying operation during the session.
func GenerateKeyPair() (pub *[64]byte, priv *[64]byte, err error) {
	pub = new([64]byte)
	priv = new([64]byte)

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

// Close zeroises the keys in the session. Once a session is closed,
// the traffic that was sent over the channel can no longer be decrypted
// and any attempts at sending or receiving messages over the channel
// will fail.
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

// Rekey is used to perform the key exchange once both sides have
// exchanged their public keys. The underlying message protocol will
// need to actually initiate and carry out the key exchange, and call
// this once that is finished. The private key will be zeroised after
// calling this function. If the session is on the side that initiated
// the key exchange (e.g. by calling Dial), it should set the dialer
// argument to true. This will also reset the message counters for the
// session, as it will cause the session to use a new key.
func (s *Session) Rekey(peer *[64]byte, dialer bool) {
	// This function denotes the dialer, who initiates the session,
	// as A. The listener is denoted as B. A is started using Dial,
	// and B is started using Listen.
	if dialer {
		// The first 32 bytes are the A->B link, where A is the
		// dialer. This key material should be used to set up the
		// A send key.
		keyExchange(s.sendKey, s.priv[:32], peer[:32])

		// The last 32 bytes are the B->A link, where A is the
		// dialer. This key material should be used to set up the A
		// receive key.
		keyExchange(s.recvKey, s.priv[32:], peer[32:])
	} else {
		// The first 32 bytes are the A->B link, where A is the
		// dialer. This key material should be used to set up the
		// B receive key.
		keyExchange(s.recvKey, s.priv[:32], peer[:32])

		// The last 32 bytes are the B->A link, where A is the
		// dialer. This key material should be used to set up the
		// B send key.
		keyExchange(s.sendKey, s.priv[32:], peer[32:])
	}
	s.lastSent = 0
	s.lastRecv = 0
}

// SessionKeySize contains the size of the identity public key, the
// session key, and the signature size.
const SessionKeySize = ed25519.PublicKeySize + 64 + ed25519.SignatureSize

const blobDataSize = ed25519.PublicKeySize + 64

// NewSession creates a new session, and returns a signed key blob
// that should be sent to the peer.
func (id *Identity) NewSession() (*[SessionKeySize]byte, *Session, error) {
	s := &Session{
		sendKey: new([32]byte),
		recvKey: new([32]byte),
	}

	pub, priv, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Store the key here until the session is complete.
	s.priv = priv

	signedBlob := new([SessionKeySize]byte)
	copy(signedBlob[:], id.public[:])
	copy(signedBlob[ed25519.PublicKeySize:], pub[:])
	sig := ed25519.Sign(id.private, signedBlob[:blobDataSize])
	copy(signedBlob[blobDataSize:], sig[:])
	return signedBlob, s, nil
}

// VerifySessionKey authenticates a session key.
func (id *Identity) VerifySessionKey(sk *[SessionKeySize]byte) (*[64]byte, bool) {
	peerID := new([ed25519.PublicKeySize]byte)
	keyData := new([64]byte)
	signature := new([ed25519.SignatureSize]byte)
	copy(peerID[:], sk[:])
	copy(keyData[:], sk[ed25519.PublicKeySize:])
	copy(signature[:], sk[blobDataSize:])

	var found bool
	for i := range id.peers {
		if subtle.ConstantTimeCompare(id.peers[i][:], peerID[:]) == 1 {
			found = true
		}
	}

	if !found {
		if id.PeerLookup != nil {
			if !id.PeerLookup(peerID) {
				return nil, false
			}
		} else {
			return nil, false
		}
	}

	if !ed25519.Verify(peerID, sk[:blobDataSize], signature) {
		return nil, false
	}

	return keyData, true
}

// ErrVerification is returned when the session key for a peer could
// not be authenticated.
var ErrVerification = errors.New("sessions: could not authenticate peer")

// Dial sets up a new session over the channel.
func (id *Identity) Dial(ch Channel) (*Session, error) {
	sk, s, err := id.NewSession()
	if err != nil {
		return nil, err
	}

	if _, err = ch.Write(sk[:]); err != nil {
		return nil, err
	}

	sk = new([SessionKeySize]byte)
	if _, err = io.ReadFull(ch, sk[:]); err != nil {
		return nil, err
	}

	peer, ok := id.VerifySessionKey(sk)
	if !ok {
		return nil, ErrVerification
	}

	s.Rekey(peer, true)
	s.Channel = ch
	return s, nil
}

// Listen accepts an incoming session setup from a dialer and attempts
// to establish a new session.
func (id *Identity) Listen(ch Channel) (*Session, error) {
	sk := new([SessionKeySize]byte)
	if _, err := io.ReadFull(ch, sk[:]); err != nil {
		return nil, err
	}

	peer, ok := id.VerifySessionKey(sk)
	if !ok {
		return nil, ErrVerification
	}

	sk, s, err := id.NewSession()
	if err != nil {
		return nil, err
	}

	if _, err = ch.Write(sk[:]); err != nil {
		return nil, err
	}

	s.Rekey(peer, false)
	s.Channel = ch
	return s, nil
}
