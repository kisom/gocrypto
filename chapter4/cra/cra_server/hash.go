package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"
)

var Password string

func randomNumber() uint64 {
	max := big.NewInt((math.MaxInt64))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic("couldn't generate random value: " + err.Error())
	}
	res := uint64(n.Int64())
	return res
}

func hash(data string) (h []byte) {
	c := sha256.New()
	c.Write([]byte(data))
	binHash := c.Sum(nil)

	h = make([]byte, 0)
	for _, b := range binHash {
		ch := fmt.Sprintf("%02x", b)
		h = append(h, []byte(ch)...)
	}
	return
}

func validateChallenge(chal string, resp string) bool {
	data := fmt.Sprintf("%s%s", Password, chal)
	data = string(hash(data))

	if data != resp {
		return false
	}
	return true
}
