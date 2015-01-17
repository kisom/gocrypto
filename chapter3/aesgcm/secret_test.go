package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

var (
	testMessage = []byte("Do not go gentle into that good night.")
	testKey     []byte
)

/*
 * The following tests verify the positive functionality of this package:
 * can an encrypted message be decrypted?
 */

func TestGenerateKey(t *testing.T) {
	var err error
	testKey, err = GenerateKey()
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestEncrypt(t *testing.T) {
	ct, err := Encrypt(testKey, testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	pt, err := Decrypt(testKey, ct)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(testMessage, pt) {
		t.Fatalf("messages don't match")
	}
}

/*
 * The following tests verify the negative functionality of this package:
 * does it fail when it should?
 */

func prngTester(size int, testFunc func()) {
	prng := rand.Reader
	buf := &bytes.Buffer{}

	rand.Reader = buf
	defer func() { rand.Reader = prng }()

	for i := 0; i < size; i++ {
		tmp := make([]byte, i)
		buf.Write(tmp)
		testFunc()
	}
}

func TestPRNGFailures(t *testing.T) {
	testFunc := func() {
		_, err := GenerateKey()
		if err == nil {
			t.Fatal("expected key generation failure with bad PRNG")
		}
	}
	prngTester(KeySize, testFunc)

	testFunc = func() {
		_, err := GenerateNonce()
		if err == nil {
			t.Fatal("expected nonce generation failure with bad PRNG")
		}
	}
	prngTester(NonceSize, testFunc)

	testFunc = func() {
		_, err := Encrypt(testKey, testMessage)
		if err == nil {
			t.Fatal("expected encryption failure with bad PRNG")
		}
	}
	prngTester(NonceSize, testFunc)
}

func TestDecryptFailures(t *testing.T) {
	targetLength := NonceSize

	for i := 0; i < targetLength; i++ {
		buf := make([]byte, i)
		if _, err := Decrypt(testKey, buf); err == nil {
			t.Fatal("expected decryption failure with bad message length")
		}
	}

	otherKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("%v", err)
	}

	ct, err := Encrypt(testKey, testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if _, err = Decrypt(otherKey, ct); err == nil {
		t.Fatal("decrypt should fail with wrong key")
	}
}

/*
 * Test AEAD parts.
 */

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

	nonce, err := GenerateNonce()
	if err != nil {
		return nil, ErrEncrypt
	}

	buf = append(buf, nonce...)
	buf = gcm.Seal(buf, nonce, message, buf[:4])
	return buf, nil
}

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

var keyList = map[uint32][]byte{}

func SelectKeyForID(id uint32) ([]byte, bool) {
	k, ok := keyList[id]
	return k, ok
}

func TestEncryptWithID(t *testing.T) {
	keyList[42] = testKey
	keyList[43] = testKey

	ct, err := EncryptWithID(testKey, testMessage, 42)
	if err != nil {
		t.Fatalf("%v", err)
	}

	out, err := DecryptWithID(ct)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(out, testMessage) {
		t.Fatal("messages don't match")
	}

	newSender := make([]byte, 4)
	binary.BigEndian.PutUint32(newSender, 43)
	for i := 0; i < 4; i++ {
		ct[i] = newSender[i]
	}

	_, err = DecryptWithID(ct)
	if err == nil {
		t.Fatal("decryption should fail with invalid AD")
	}
}
