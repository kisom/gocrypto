package armour

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"testing"
)

var (
	ErrEncoding = fmt.Errorf("bad base64 encoding")
	ErrDecoding = fmt.Errorf("base base64 decoding")
	ErrNoMatch  = fmt.Errorf("returned doesn't match expected value")
)

func init() {
	fUseUrlEncoding := flag.Bool("url", false, "select URLEncoding scheme")
	flag.Parse()

	if *fUseUrlEncoding {
		fmt.Println("[+] URLEncoding selected")
		Encoding = base64.URLEncoding
	}
}

func TestBase64Encode(t *testing.T) {
	fmt.Printf("Base64Encode: ")

	const testVector = "Hello, gophers."
	const expected = "SGVsbG8sIGdvcGhlcnMu"
	var testInput = []byte(testVector)

	encoded := EncodeBase64(testInput)
	if string(encoded) != expected {
		FailWithError(t, ErrEncoding)
	}
	fmt.Println("ok")
}

func TestBase64Decode(t *testing.T) {
	fmt.Printf("Base64Decode: ")

	const expected = "Hello, gophers."
	const testVector = "SGVsbG8sIGdvcGhlcnMu"

	decoded, err := DecodeBase64([]byte(testVector))
	if err != nil {
		FailWithError(t, err)
	} else if expected != string(decoded) {
		FailWithError(t, ErrDecoding)
	}
	fmt.Println("ok")
}

func TestBase64EncodeDecode(t *testing.T) {
	fmt.Printf("Base64Encode+Decode: ")

	const testVector = "Hello, gophers."
	out, err := DecodeBase64(EncodeBase64([]byte(testVector)))
	if err != nil {
		FailWithError(t, err)
	} else if string(out) != testVector {
		FailWithError(t, ErrNoMatch)
	}
	fmt.Println("ok")
}

func TestBase64EncodeReader(t *testing.T) {
	fmt.Printf("Base64EncodeReader: ")

	const testVector = "Hello, gophers."
	const expected = "SGVsbG8sIGdvcGhlcnMu"

	r := bytes.NewBuffer([]byte(testVector))
	w := new(bytes.Buffer)

	err := EncodeBase64Reader(w, r)
	if err != nil {
		FailWithError(t, err)
	} else if string(w.Bytes()) != expected {
		FailWithError(t, ErrEncoding)
	}
	fmt.Println("ok")
}

func TestBase64DecodeReader(t *testing.T) {
	fmt.Printf("Base64DecodeReader: ")

	const expected = "Hello, gophers."
	const testVector = "SGVsbG8sIGdvcGhlcnMu"

	r := bytes.NewBuffer([]byte(testVector))
	w := new(bytes.Buffer)

	err := DecodeBase64Reader(w, r)
	if err != nil {
		FailWithError(t, err)
	} else if string(w.Bytes()) != expected {
		FailWithError(t, ErrEncoding)
	}
	fmt.Println("ok")
}
