package hash

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

var (
	helloTestVector = []byte("Hello, world.")
	helloBinDigest  = []byte{12, 10, 21, 6, 104, 202, 124, 195, 102,
		123, 140, 102, 87, 218, 210, 43, 210, 167, 25, 82, 167,
		134, 76, 144, 109, 230, 222, 255, 213, 81, 101, 159, 248, 239,
		138, 241, 51, 95, 130, 250, 247, 168, 232, 132, 129, 131, 234,
		239, 55, 42, 11, 175, 69, 79, 208, 206, 195, 9, 146, 57, 230,
		147, 24, 128}
	helloHexDigest = "0c0a150668ca7cc3667b8c6657dad22bd2a71952a7864c906de6deffd551659ff8ef8af1335f82faf7a8e8848183eaef372a0baf454fd0cec3099239e6931880"
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
