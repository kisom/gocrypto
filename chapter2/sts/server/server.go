package main

import (
	"flag"
	"fmt"
	"github.com/kisom/gocrypto/chapter2/symmetric"
	"io/ioutil"
	"log"
	"net"
	"time"
)

var (
	Key     []byte
	Address string
)

func init() {
	keyFile := flag.String("k", "server.key", "server's key")
	port := flag.Int("p", 4141, "port to listen on")
	host := flag.String("a", "", "address to listen on")
	flag.Parse()
	Address = fmt.Sprintf("%s:%d", *host, *port)

	var err error
	Key, err = ioutil.ReadFile(*keyFile)
	if err != nil {
		panic(err.Error())
	}
}

func timeMessage() (msg []byte) {
	now := []byte(fmt.Sprintf("%d", time.Now().Unix()))
	log.Printf("plaintext: %s\n", string(now))
	msgEncrypted, err := symmetric.Encrypt(Key, now)
	if err != nil {
		panic(err.Error())
	}

	msg = msgEncrypted.ToBytes()
	return
}

func sendTime(conn net.Conn) {
	conn.Write(timeMessage())
	conn.Close()
}

func main() {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", Address)
	if err != nil {
		panic(err.Error())
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		panic(err.Error())
	}

	log.Println("listening on ", Address)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err.Error())
		}
		go sendTime(conn)
	}
}
