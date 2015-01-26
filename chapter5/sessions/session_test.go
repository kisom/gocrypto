package sessions

import (
	"bytes"
	"testing"

	"github.com/agl/ed25519"
	"github.com/kisom/cryptutils/common/util"
	"github.com/kisom/testio"
)

// alice and bob are friends
// carol is that poor schmuck out in the cold. sorry, carol.
var alice, bob, carol *Identity

func TestNewIdentity(t *testing.T) {
	var err error
	alice, err = NewIdentity()
	if err != nil {
		t.Fatalf("%v", err)
	}

	bob, err = NewIdentity()
	if err != nil {
		t.Fatalf("%v", err)
	}
	alice.AddPeer(bob.Public())
	bob.AddPeer(alice.Public())
	bob.AddPeer(alice.Public())
	if len(bob.peers) != 1 {
		t.Fatal("duplicate peers added")
	}

	carol, err = NewIdentity()
	if err != nil {
		t.Fatalf("%v", err)
	}
	carol.AddPeer(bob.Public())

	aliceOut := Marshal(alice)
	if _, err = Unmarshal(aliceOut); err != nil {
		t.Fatalf("%v", err)
	}

	for i := 0; i < 100; i++ {
		if i == 96 {
			// A pair of keys with no peer list is valid.
			continue
		}
		bs := make([]byte, i)
		if _, err = Unmarshal(bs); err == nil {
			t.Fatal("unmarshal should have failed")
		}
	}

	bs := make([]byte, 158)
	if _, err = Unmarshal(bs); err == nil {
		t.Fatal("unmarshal should have failed")
	}
}

var m = []byte(`good men, the last wave bye crying how bright
their frail deeds might have danced in a green bay
rage, rage against the dying of the light`)

func TestDial(t *testing.T) {
	conn := testio.NewBufferConn()
	sk, bs, err := bob.NewSession()
	if err != nil {
		t.Fatalf("%v", err)
	}

	conn.WritePeer(sk[:])
	as, err := alice.Dial(conn)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var ask [SessionKeySize]byte
	_, err = conn.ReadClient(ask[:])
	if err != nil {
		t.Fatalf("%v", err)
	}

	peer, ok := bob.VerifySessionKey(&ask)
	if !ok {
		t.Fatal("alice wasn't trusted by bob")
	}

	bs.Rekey(peer, false)
	buf := &bytes.Buffer{}
	as.Channel = buf
	bs.Channel = as.Channel

	err = as.Send(m)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// TLA intercepted a message.
	first := buf.Bytes()

	rcv, err := bs.Receive()
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(rcv, m) {
		t.Fatal("bob didn't get the right message")
	}

	for i := 0; i < 5; i++ {
		err = as.Send(m)
		if err != nil {
			t.Fatalf("%v", err)
		}

		rcv, err = bs.Receive()
		if err != nil {
			t.Fatalf("%v", err)
		}

		if !bytes.Equal(rcv, m) {
			t.Fatal("bob didn't get the right message")
		}
	}

	// TLA tries to replay message.
	as.Channel.Write(first)
	_, err = bs.Receive()
	if err == nil {
		t.Fatal("TLA wins.")
	}
	// \o/

	bs.Close()
	as.Close()
}

func TestListen(t *testing.T) {
	conn := testio.NewBufferConn()
	sk, bs, err := bob.NewSession()
	if err != nil {
		t.Fatalf("%v", err)
	}

	conn.WritePeer(sk[:])
	as, err := alice.Listen(conn)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var ask [SessionKeySize]byte
	_, err = conn.ReadClient(ask[:])
	if err != nil {
		t.Fatalf("%v", err)
	}

	peer, ok := bob.VerifySessionKey(&ask)
	if !ok {
		t.Fatal("alice wasn't trusted by bob")
	}

	bs.Rekey(peer, true)
	buf := &bytes.Buffer{}
	as.Channel = buf
	bs.Channel = as.Channel

	err = as.Send(m)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// TLA intercepted a message.
	first := buf.Bytes()

	rcv, err := bs.Receive()
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(rcv, m) {
		t.Fatal("bob didn't get the right message")
	}

	for i := 0; i < 5; i++ {
		err = as.Send(m)
		if err != nil {
			t.Fatalf("%v", err)
		}

		rcv, err = bs.Receive()
		if err != nil {
			t.Fatalf("%v", err)
		}

		if !bytes.Equal(rcv, m) {
			t.Fatal("bob didn't get the right message")
		}
	}

	// TLA tries to replay message.
	as.Channel.Write(first)
	_, err = bs.Receive()
	if err == nil {
		t.Fatal("TLA wins.")
	}
	// \o/

	bs.Close()
	as.Close()
}

func TestUntrusted(t *testing.T) {
	conn := testio.NewBufferConn()
	sk, _, err := bob.NewSession()
	if err != nil {
		t.Fatalf("%v", err)
	}

	conn.WritePeer(sk[:])
	_, err = carol.Dial(conn)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var csk [SessionKeySize]byte
	_, err = conn.ReadClient(csk[:])
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, ok := bob.VerifySessionKey(&csk)
	if ok {
		t.Fatal("carol should not be trusted by bob")
	}
}

func TestPeerLookup(t *testing.T) {
	bob.PeerLookup = func(k *[ed25519.PublicKeySize]byte) bool {
		return false
	}

	conn := testio.NewBufferConn()
	sk, _, err := bob.NewSession()
	if err != nil {
		t.Fatalf("%v", err)
	}

	conn.WritePeer(sk[:])
	_, err = carol.Dial(conn)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var csk [SessionKeySize]byte
	_, err = conn.ReadClient(csk[:])
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, ok := bob.VerifySessionKey(&csk)
	if ok {
		t.Fatal("carol should not be trusted by bob")
	}

	bob.PeerLookup = func(k *[ed25519.PublicKeySize]byte) bool {
		return true
	}

	conn = testio.NewBufferConn()
	sk, _, err = bob.NewSession()
	if err != nil {
		t.Fatalf("%v", err)
	}

	conn.WritePeer(sk[:])
	_, err = carol.Dial(conn)
	if err != nil {
		t.Fatalf("%v", err)
	}

	util.Zero(csk[:])
	_, err = conn.ReadClient(csk[:])
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, ok = bob.VerifySessionKey(&csk)
	if !ok {
		t.Fatal("carol should be trusted by bob")
	}

	bob.PeerLookup = nil
}
