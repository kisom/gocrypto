package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
)

var (
	Key        []byte
	Message    []byte
	Ciphertext []byte
)

func main() {
	addr := flag.String("addr", ":8080", "address for HTTP server")
	dictPath := flag.String("dict", "/usr/share/dict/words", "path to dictionary")
	flag.Parse()

	buildMessage(*dictPath)
	Key = NewKey()
	if Key == nil {
		log.Fatal("failed to generate key")
	}

	var err error
	Ciphertext, err = Encrypt(Key, Message)
	if err != nil {
		log.Fatal("failed to encrypt message: %v", err)
	}

	http.HandleFunc("/check", checkMessage)
	http.HandleFunc("/ciphertext", sendCiphertext)
	http.HandleFunc("/decrypt", decrypt)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func sendCiphertext(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}
	out := make([]byte, hex.EncodedLen(len(Ciphertext)))
	hex.Encode(out, Ciphertext)
	w.Write(out)
}

// There is another side-channel attack here.
func checkMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("failed to read body: %v", err)
		return
	}
	r.Body.Close()
	if bytes.Equal(body, Message) {
		w.Write([]byte("You win!"))
	} else {
		w.Write([]byte("Try again"))
	}
}

func decrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("failed to read body: %v", err)
		return
	}
	r.Body.Close()

	_, err = Decrypt(Key, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write([]byte("OK"))
}
