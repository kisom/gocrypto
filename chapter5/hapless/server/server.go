// HAP server
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

	challenge := hap.Challenge()
	_, err := conn.Write([]byte(challenge))
	if err != nil {
		log.Println("[!] error sending challenge:", err.Error())
		return
	}

	response := make([]byte, hap.ResponseLength)
	n, err := conn.Read(response)
	if err != nil {
		log.Println("[!] error reading response from client:", err.Error())
		return
	} else {
		response = response[:n]
	}

	if !hap.Validate(password, challenge, response) {
		log.Println("[!] client failed authentication")
		return
	}

	conn.Write([]byte("ok"))

	srvChal := make([]byte, hap.ResponseLength)
	n, err = conn.Read(srvChal)
	if err != nil {
		log.Println("[!] error reading challenge from client:", err.Error())
		return
	} else {
		srvChal = srvChal[:n]
	}

	srvResponse := hap.Response(password, string(srvChal))
	_, err = conn.Write([]byte(srvResponse))
	if err != nil {
		log.Println("[!] failed to send response:", err.Error())
		return
	}

	ok := make([]byte, 2)
	_, err = conn.Read(ok)
	if err != nil {
		log.Println("failed to receive acknowledgement")
		return
	}

	request := make([]byte, RequestLength)
	n, err = conn.Read(request)
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
