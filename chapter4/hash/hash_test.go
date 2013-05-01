package hash

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

var (
	helloTestVector = []byte("Hello, world.")
	helloBinDigest  = []byte{173, 12, 55, 195, 29, 105, 179, 21,
                243, 168, 31, 19, 200, 205, 231, 1, 9, 74, 217, 23, 37,
                186, 27, 13, 195, 25, 156, 169, 113, 54, 97, 184, 40,
                13, 110, 247, 230, 143, 19, 62, 98, 17, 226, 229, 169,
                163, 21, 4, 69, 215, 111, 23, 8, 224, 69, 33, 176, 238,
                3, 79, 11, 11, 175, 38}
	helloHexDigest = "ad0c37c31d69b315f3a81f13c8cde701094ad91725ba1b0dc3199ca9713661b8280d6ef7e68f133e6211e2e5a9a3150445d76f1708e04521b0ee034f0b0baf26"
)

func GenFailer(name string, err error, t *testing.T) func(string) {
	return func(msg string) {
		if msg == "" {
			fmt.Printf("%s: failed: %s\n", name, err.Error())
		} else {
			fmt.Printf("%s: failed: %s\n", name, msg)
		}
		t.FailNow()
	}
}

func sampleReader(src []byte) io.Reader {
	if src == nil {
		src = helloTestVector
	}
	b := bytes.NewBuffer(src)
	return b
}

func TestNewHash(t *testing.T) {
	fail := GenFailer("TestNewHash", nil, t)
	h := New(helloTestVector)
	if !bytes.Equal(h.Digest(), helloBinDigest) {
		fail("test vector doesn't match hash")
	}

	if string(h.HexDigest()) != helloHexDigest {
		fail("test hex digest doesn't match hash")
	}
}

func TestReadHash(t *testing.T) {
	var err error

	fail := GenFailer("TestReadHash", err, t)
	r := sampleReader(nil)
	h, err := Read(r)
	if err != nil {
		fail("")
	} else if !bytes.Equal(h.Digest(), helloBinDigest) {
		fail("test vector doesn't match hash")
	}
}

func TestVerifyHash(t *testing.T) {
	fail := GenFailer("TestVerifyHash", nil, t)
	h := New(helloTestVector)
	if !h.Verify(helloTestVector) {
		fail("Verify() failed for test vector")
	} else if h.Verify([]byte("Hello, world?")) {
		fail("Verify() should have failed for test vector")
	}
}

func TestVerifyReadHash(t *testing.T) {
	fail := GenFailer("TestVerifyReadHash", nil, t)
	r := sampleReader(nil)

	h := New(helloTestVector)
	if !h.VerifyRead(r) {
		fail("VerifyRead() failed for test vector")
	}

	r = sampleReader([]byte("Hello, world?"))
	if h.VerifyRead(r) {
		fail("VerifyRead() should have failed for test vector")
	}
}
