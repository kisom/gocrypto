package main

import (
	"flag"
	"github.com/kisom/gocrypto/chapter5/hap"
	"log"
	"net"
)

const RequestLength = 32

var password string

func authenticate(conn net.Conn) {
	defer conn.Close()

	err := hap.Challenge(conn, password)
	if err != nil {
		log.Println("challenge failed:", err.Error())
		return
	}

	err = hap.Authenticate(conn, password)
	if err != nil {
		log.Println("authentication failed:", err.Error())
		return
	}

	request := make([]byte, RequestLength)
	_, err = conn.Read(request)
	if err != nil {
		log.Println("error reading client request:", err.Error())
		return
	}
	log.Println("client request:", string(request))
}

func server(address string) {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil {
		panic(err.Error())
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Fatal("failed to set up listener:", err.Error())
	}

	log.Println("server listening on", address)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err.Error())
		}
		go authenticate(conn)
	}
	log.Println("server shuts down")
}

func main() {
	fPass := flag.String("p", "", "server password")
	fAddress := flag.String("a", ":4141", "address to listen on in <ip>:port format")
	flag.Parse()

	if *fPass == "" {
		log.Fatal("no password supplied: not starting")
	}
	password = *fPass

	server(*fAddress)
}
