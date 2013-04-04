package main

import (
        "crypto/sha256"
        "fmt"
)

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

