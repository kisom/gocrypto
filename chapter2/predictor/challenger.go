package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

var iv = make([]byte, aes.BlockSize)

// KeySize is size of AES-256-CBC keys in bytes.
const KeySize = 32

func randBytes(size int) []byte {
	p := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, p)
	if err != nil {
		p = nil
	}
	return p
}

// GenerateIV provides new IVs. The default function returns randomly
// generated IVs.
func NextIV() {
	for i := aes.BlockSize - 1; i >= 0; i-- {
		if iv[i]++; iv[i] != 0 {
			return
		}
	}
}

// NewKey randomly randomly generates a new key.
func NewKey() []byte {
	return randBytes(KeySize)
}

// Pad applies the PKCS #7 padding scheme on the buffer.
func Pad(in []byte) []byte {
	padding := 16 - (len(in) % 16)
	if padding == 0 {
		padding = 16
	}
	for i := 0; i < padding; i++ {
		in = append(in, byte(padding))
	}
	return in
}

// Unpad strips the PKCS #7 padding on a buffer. If the padding is
// invalid, nil is returned.
func Unpad(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}

	padding := in[len(in)-1]
	if int(padding) > len(in) || padding > aes.BlockSize {
		return nil
	}

	for i := len(in) - 1; i > len(in)-int(padding); i-- {
		if in[i] != padding {
			return nil
		}
	}
	return in[:len(in)-int(padding)]
}

var Key []byte

// Encrypt applies the necessary padding to the message and encrypts it
// with AES-CBC.
func Encrypt(in []byte) ([]byte, bool) {
	defer NextIV()
	in = Pad(in)

	c, err := aes.NewCipher(Key)
	if err != nil {
		return nil, false
	}

	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(in, in)
	return append(iv, in...), true
}

func init() {
	Key = NewKey()
	if Key == nil {
		panic("Failed to generate master key!")
	}
}

type Query struct {
	M1     []byte `json:"m1"`
	M2     []byte `json:"m2"`
	choice bool
}

var lastQuery = &Query{}

func selectFirst() bool {
	for {
		bs := randBytes(1)
		if bs == nil {
			panic("Failed to read random data.")
		} else if bs[0] > 250 {
			continue
		}
		log.Printf("flipping coin: %v", bs[0]%2 == 0)
		return bs[0]%2 == 0
	}
}

func fail(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("internal error"))
}

func receiveMessage(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err.Error())
	}
	r.Body.Close()

	lastQuery = new(Query)
	err = json.Unmarshal(body, lastQuery)
	if err != nil {
		log.Printf("bad JSON request: %v", err)
		fail(w)
		return
	}

	var m []byte
	if lastQuery.choice = selectFirst(); lastQuery.choice {
		m = lastQuery.M1
	} else {
		m = lastQuery.M2
	}

	ct, ok := Encrypt(m)
	if !ok {
		log.Println("encryption failure")
		fail(w)
		return
	}

	w.Write([]byte(fmt.Sprintf("%x", ct)))
}

type Guess struct {
	First bool `json:"first"`
}

func choose(w http.ResponseWriter, r *http.Request) {
	log.Printf("attacker is making a choice")
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err.Error())
	}
	r.Body.Close()

	var guess Guess
	err = json.Unmarshal(body, &guess)
	if err != nil {
		log.Printf("bad JSON request: %v", err)
		fail(w)
		return
	}

	if guess.First == lastQuery.choice {
		log.Println("attacker chose correctly")
		w.Write([]byte("1"))
	} else {
		log.Println("attacker chose incorrectly")
		w.Write([]byte("0"))
	}
}

func main() {
	addr := flag.String("a", ":8080", "listening address (host:port)")
	flag.Parse()

	log.Println("starting server on", *addr)
	http.HandleFunc("/query", receiveMessage)
	http.HandleFunc("/choose", choose)
	http.ListenAndServe(*addr, nil)
}
