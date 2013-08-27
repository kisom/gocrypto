package forwardsec

import "bytes"
import "crypto/rsa"
import "fmt"
import "testing"

var (
	Alice *IdentityKey
	Bob   *IdentityKey
	APub  *rsa.PublicKey
	BPub  *rsa.PublicKey
)

func init() {
	if Alice = NewIdentityKey(); Alice == nil {
		panic("Failed to generate identity key.")
	} else if Bob = NewIdentityKey(); Bob == nil {
		panic("Failed to generate identity key.")
	}
}

var aliceSession, bobSession *SessionKey

func TestSessionKey(t *testing.T) {
	if aliceSession = Alice.NewSessionKey(); aliceSession == nil {
		fmt.Println("forwardsec: failed to generate session key for Alice.")
		t.FailNow()
	}
	if bobSession = Bob.NewSessionKey(); bobSession == nil {
		fmt.Println("forwardsec: failed to generate session key for Bob.")
		t.FailNow()
	}

	APub = ImportPeerIdentity(Bob.Public())
	BPub = ImportPeerIdentity(Alice.Public())
	if APub == nil || BPub == nil {
		fmt.Println("forwardsec: failed to import peer identity.")
		t.FailNow()
	}

	if err := aliceSession.PeerSessionKey(APub, bobSession.Public()); err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
	if err := bobSession.PeerSessionKey(BPub, aliceSession.Public()); err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
}

type testCase struct {
	Message []byte
	CText   []byte
}

// Alice -> Bob
var aliceMessage = testCase{
	Message: []byte("This is a test message from Alice to Bob."),
}

// Bob -> Alice
var bobMessage = testCase{
	Message: []byte("This is a test message from Bob to Alice."),
}

func TestEncryptAliceToBob(t *testing.T) {
	var err error
	aliceMessage.CText, err = aliceSession.Encrypt(aliceMessage.Message)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	msg, err := bobSession.Decrypt(aliceMessage.CText)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if !bytes.Equal(msg, aliceMessage.Message) {
		fmt.Println("forwardsec: bad decryption")
		t.FailNow()
	}
}

func TestEncryptBobToAlice(t *testing.T) {
	var err error
	bobMessage.CText, err = bobSession.Encrypt(bobMessage.Message)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	msg, err := aliceSession.Decrypt(bobMessage.CText)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if !bytes.Equal(msg, bobMessage.Message) {
		fmt.Println("forwardsec: bad decryption")
		t.FailNow()
	}
}
