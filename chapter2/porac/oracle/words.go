package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"io/ioutil"
	"log"
	mrand "math/rand"
)

func seed() {
	var seed = make([]byte, 8)
	_, err := io.ReadFull(rand.Reader, seed)
	if err != nil {
		log.Fatalf("FATAL: %v", err)

	}

	seedVal := int64(binary.BigEndian.Uint64(seed))
	mrand.Seed(seedVal)
}

func buildMessage(dict string) {
	var words [][]byte
	in, err := ioutil.ReadFile(dict)
	if err != nil {
		log.Fatalf("can't build message: %v\n", err)
	}
	in = bytes.TrimSpace(in)
	inSlice := bytes.Split(in, []byte{0xa})

	mLen := mrand.Intn(15) + 5
	for i := 0; i < mLen; i++ {
		words = append(words, inSlice[mrand.Intn(len(inSlice))])
	}
	Message = bytes.Join(words, []byte(" "))
}

func init() {
	seed()
}
