package main

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

var servAddr = "127.0.0.1:8080"

func fetchCiphertext() (ct []byte, err error) {
	url := "http://" + servAddr + "/ciphertext"
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}
	ct = make([]byte, hex.DecodedLen(len(body)))
	_, err = hex.Decode(ct, body)
	return
}

func sendCiphertext(blocks [][]byte) (status int, body []byte, err error) {
	ct := bytes.Join(blocks, []byte{})
	buf := bytes.NewBuffer(ct)
	url := "http://" + servAddr + "/decrypt"
	resp, err := http.Post(url, "application/x-www-form-urlencoded", buf)
	if err != nil {
		return
	}
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	status = resp.StatusCode
	return
}

func checkPlaintext(pt []byte) (status int, body []byte, err error) {
	buf := bytes.NewBuffer(pt)
	url := "http://" + servAddr + "/check"
	resp, err := http.Post(url, "application/x-www-form-urlencoded", buf)
	if err != nil {
		return
	}
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	status = resp.StatusCode
	return
}

func splitCiphertext(ct []byte) [][]byte {
	var blocks [][]byte
	ctp := ct
	for {
		if len(ctp) == 0 {
			break
		}
		blocks = append(blocks, ctp[:aes.BlockSize])
		ctp = ctp[aes.BlockSize:]
	}
	return blocks
}

func recoverBlock(blocks [][]byte) []byte {
	nBlocks := len(blocks) - 1
	var ptBlock = make([]byte, aes.BlockSize)
	var newBlocks = [][]byte{make([]byte, aes.BlockSize), blocks[nBlocks]}
	for n := aes.BlockSize - 1; n >= 0; n-- {
		xorBlock := byte(aes.BlockSize - n)
		var found bool
		for i := 0; i < 255; i++ {
			newBlocks[0][n] = byte(i)
			status, _, err := sendCiphertext(newBlocks)
			if err != nil {
				log.Fatalf("fatal error: %v", err)
			} else if status == 200 {
				log.Printf("candidate: %x", i)
				ptBlock[n] = xorBlock ^ blocks[nBlocks-1][n] ^ byte(i)
				found = true
				break
			}
		}
		if !found {
			log.Fatalf("failed on byte %d pt: %x", n, ptBlock)
		}
		for i := n; i < aes.BlockSize; i++ {
			newBlocks[0][i] = (xorBlock + 1) ^ blocks[nBlocks-1][i] ^ ptBlock[i]
		}
	}
	return ptBlock
}

func main() {
	addr := flag.String("addr", servAddr, "server address")
	flag.Parse()
	servAddr = *addr

	ct, err := fetchCiphertext()
	if err != nil {
		log.Fatalf("failed to retrieve ciphertext: %v", err)
	}
	log.Printf("retrieve %d bytes of ciphertext", len(ct))

	blocks := splitCiphertext(ct)
	var s = "\n\t"
	for i := 0; i < len(blocks); i++ {
		for j := 0; j < len(blocks[i]); j++ {
			s += fmt.Sprintf("%02x ", blocks[i][j])
		}
		s += "\n\t"
	}
	log.Printf("blocks: %s", s)
	log.Printf("ciphertext is %d blocks", len(blocks))
	status, body, err := sendCiphertext(blocks)
	if err != nil {
		log.Fatalf("sending ciphertext failed")
	}
	log.Printf("status: %d", status)
	log.Printf("response: %s", string(body))

	poBlocks := blocks
	var plaintext []byte
	for {
		if len(poBlocks) > 1 {
			pt := recoverBlock(poBlocks)
			log.Printf("recovered plaintext block %v", pt)
			plaintext = append(pt, plaintext...)
			poBlocks = poBlocks[:len(poBlocks)-1]
		} else {
			break
		}
	}
	padByte := string(plaintext[len(plaintext)-1])
	plaintext = bytes.TrimRight(plaintext, padByte)
	log.Printf("plaintext: %s", string(plaintext))

	log.Printf("Submitting plaintext... ")
	log.Printf("curl -d '%s' http://%s/check", string(plaintext), servAddr)
	status, body, err = checkPlaintext(plaintext)
	if err != nil {
		log.Printf("fatal error checking plaintext: %v", err)
	} else if status == http.StatusOK {
		log.Println("SUCCESS")
		log.Printf("server replies with '%s'", string(body))
	} else {
		log.Println("FAILED")
		log.Printf("server replies with '%s'", string(body))
	}

}
