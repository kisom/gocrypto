package session

import (
	"bytes"
	"crypto/rand"
	"testing"

	"git.metacircular.net/kyle/gocrypto/util"
	"github.com/kisom/testio"
	"golang.org/x/crypto/nacl/box"
)

var (
	alicePub, alicePriv *[32]byte
	bobPub, bobPriv     *[32]byte
)

func TestGenerateKeys(t *testing.T) {
	var err error

	alicePub, alicePriv, err = box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}

	bobPub, bobPriv, err = box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

var (
	testMessage = []byte("do not go gentle into that good night")
	testSecured []byte

	aliceSession, bobSession *Session
)

func TestSessionSetup(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("%v", err)
	}

	conn := testio.NewBufferConn()
	conn.WritePeer(pub[:])

	aliceSession, err = Dial(conn)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var peer [64]byte
	_, err = conn.ReadClient(peer[:])
	if err != nil {
		t.Fatalf("%v", err)
	}

	bobSession = &Session{
		recvKey: new([32]byte),
		sendKey: new([32]byte),
		Channel: testio.NewBufCloser(nil),
	}

	bobSession.KeyExchange(priv, &peer, false)
	aliceSession.Channel = bobSession.Channel
	err = aliceSession.Send(testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	out, err := bobSession.Receive()
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(out, testMessage) {
		t.Fatal("recovered message doesn't match original")
	}

	if err = aliceSession.Send(nil); err == nil {
		t.Fatal("empty message should trigger an error")
	}

	aliceSession.Close()
	bobSession.Close()
}

var oldMessage []byte

func TestSessionListen(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("%v", err)
	}

	conn := testio.NewBufferConn()
	conn.WritePeer(pub[:])

	aliceSession, err = Listen(conn)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var peer [64]byte
	_, err = conn.ReadClient(peer[:])
	if err != nil {
		t.Fatalf("%v", err)
	}

	bobSession = &Session{
		recvKey: new([32]byte),
		sendKey: new([32]byte),
		Channel: testio.NewBufCloser(nil),
	}

	bobSession.KeyExchange(priv, &peer, true)

	aliceSession.Channel = bobSession.Channel
	err = aliceSession.Send(testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	out, err := bobSession.Receive()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// The NBA is always listening, on and off the court.
	oldMessage = out

	if !bytes.Equal(out, testMessage) {
		t.Fatal("recovered message doesn't match original")
	}

	for i := 0; i < 4; i++ {
		randMessage, err := util.RandBytes(128)
		if err != nil {
			t.Fatalf("%v", err)
		}

		err = aliceSession.Send(randMessage)
		if err != nil {
			t.Fatalf("%v", err)
		}

		out, err = bobSession.Receive()
		if err != nil {
			t.Fatal("%v", err)
		}

		if !bytes.Equal(out, randMessage) {
			t.Fatal("recovered message doesn't match original")
		}
	}

	// NBA injects an old message into the channel. Damn those hoops!
	bobSession.Channel.Write(oldMessage)
	_, err = bobSession.Receive()
	if err == nil {
		t.Fatal("NBA wins, you lose")
	}
}
