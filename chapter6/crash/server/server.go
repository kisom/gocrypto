package main

import (
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"os"
)

var Password string

func randomNumber() uint8 {
	max := big.NewInt(math.MaxInt8)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Println("failed to generate a random number:", err.Error())
		os.Exit(1)
	}
	res := uint8(n.Int64())
	return res
}

func hash(data string) string {
	c := sha256.New()
	_, err := c.Write([]byte(data))
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", c.Sum(nil))
}

func validateChallenge(chal string, resp string) bool {
	data := hash(Password + chal)

	if data != resp {
		return false
	}
	return true
}

func sendChallenge(conn net.Conn) {
	defer conn.Close()
	chal := fmt.Sprintf("%d", randomNumber())
	conn.Write([]byte(chal))

	resp := make([]byte, sha256.Size*2)
	n, err := conn.Read(resp)
	if err != nil {
		conn.Write([]byte("error: " + err.Error()))
		return
	} else if n != (sha256.Size * 2) {
		conn.Write([]byte("error: invalid response"))
		return
	}

	if validateChallenge(chal, string(resp)) {
		conn.Write([]byte("secret data!"))
	} else {
		conn.Write([]byte("error: authentication failed"))
	}
	return
}

func main() {
	fAddress := flag.String("a", ":4141", "server address")
	fPassword := flag.String("p", "", "password for server")
	flag.Parse()

	if *fPassword == "" {
		fmt.Println("[!] no password specified!")
		os.Exit(1)
	}
	Password = *fPassword

	server(*fAddress)
}

func server(address string) {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil {
		panic(err.Error())
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		panic(err.Error())
	}

	log.Println("listening on", address)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err.Error())
		}
		go sendChallenge(conn)
	}
}
