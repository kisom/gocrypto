package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/kisom/gocrypto/chapter2/symmetric"
	"io/ioutil"
	"log"
	"net"
	"time"
)

var (
	Key       []byte
	Address   string
	nonceChan chan []byte
)

func nonceGenerator() {
        nonceChan = make(chan []byte, 4)
        for {
                nonce, err := symmetric.GenerateIV()
                if err == nil {
                        nonceChan<- nonce
                }
        }
}

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

// converse causes the server to initiate the conversation.
func converse(conn net.Conn) {
	log.Println("conversing with client")

        nonce := <-nonceChan

	log.Println("sending nonce")
	n, err := conn.Write(nonce)
        if err != nil {
		log.Println("error writing nonce: ", err.Error())
		conn.Close()
		return
        }
        log.Printf("wrote %d bytes to client\n", n)

	log.Println("waiting on client's response")
	response, err := ioutil.ReadAll(conn)
	if err != nil {
		log.Println("error reading client response: ", err.Error())
		conn.Close()
		return
	}

	log.Println("decrypting client's response...")
	if (len(response) % symmetric.BlockSize) != 0 {
		log.Println("bad response from the client")
		conn.Close()
		return
	}
	clientNonce, err := symmetric.DecryptBytes(Key, response)
	if err != nil {
		log.Println("error decrypting response: ", err.Error())
		conn.Close()
		return
	}

	if !bytes.Equal(clientNonce, nonce) {
		log.Println("error decrypting response: ", err.Error())
		conn.Close()
		return
	}

	log.Println("sending secret")
	ts := []byte(fmt.Sprintf("%d", time.Now().Unix()))
	conn.Write(ts)
	conn.Close()
}

func main() {
        go nonceGenerator()

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
		go converse(conn)
	}
}
