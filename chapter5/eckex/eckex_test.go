package eckex

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

var (
	alice *ecdsa.PrivateKey
	bob   *ecdsa.PrivateKey
)

func TestSetupKeys(t *testing.T) {
	var err error

	alice, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}

	bob, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

var (
	abSession    *Session
	baSession    *Session
	aliceP, bobP []byte
)

func TestInitSession(t *testing.T) {
	var err error
	abSession, aliceP, err = StartKEX(alice)
	if err != nil {
		t.Fatalf("%v", err)
	}

	baSession, bobP, err = StartKEX(bob)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestABSession(t *testing.T) {
	var err error
	err = abSession.FinishKEX(&bob.PublicKey, bobP)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = baSession.FinishKEX(&alice.PublicKey, aliceP)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

var tm = []byte(`do not go gentle into that good night
old age should rave and burn at edge of day
rage, rage against the dying of the light

though wise men at their end know dark is right,
because their words had forked no lightning they
do not go gentle into that good night

good men, the last wave bye, crying how bright
their frail deeds might have danced in a green bay
rage, rage against the dying of the light

wild men, who caught and sang the sun in flight
and learned, too late, they grieved it on its way
do not go gentle into that good night

grave men, near death, who see with blinding sight
blind eyes could blaze and be gay
rage, rage against the dying of the light

and you, my father, there on that sad height
curse, bless, me now with your fierce tears, i pray
do not go gentle into that good night
rage, rage against the dying of the light
`)

func testCrypt(from, to *Session, t *testing.T) {
	out, err := from.Encrypt(tm)
	if err != nil {
		t.Fatalf("%v", err)
	}

	out, err = to.Decrypt(out)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(out, tm) {
		t.Fatal("recovered message does not match original")
	}
}

func TestEncrypt(t *testing.T) {
	testCrypt(abSession, baSession, t)
	testCrypt(baSession, abSession, t)
}

func checkZeroised(in []byte, t *testing.T, src string) {
	for i := 0; i < len(in); i++ {
		if in[i] != 0 {
			t.Fatalf("%s not zeroised at %d: %x", src, i, in)
		}
	}
}

func TestClose(t *testing.T) {
	abSession.Close()
	checkZeroised(abSession.priv, t, "alice priv")
	checkZeroised(abSession.shared, t, "alice shared")
	baSession.Close()
	checkZeroised(baSession.priv, t, "bob priv")
	checkZeroised(baSession.shared, t, "bob shared")
}
