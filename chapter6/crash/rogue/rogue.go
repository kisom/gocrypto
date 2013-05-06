package main

import (
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"net"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"
)

var (
	dbFile    string
	shutdown  chan interface{}
	errRegexp = regexp.MustCompile("^error: (.+)$")
)

func getResponse(server string, challenge []byte) (response []byte) {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		fmt.Println("[!] failed to open DB file:", err.Error())
		os.Exit(1)
	}
	defer db.Close()

	row := db.QueryRow(`select response from challenges where
                server=? and challenge=?`, server, challenge)
	err = row.Scan(&response)
	if err != nil {
		fmt.Println("[!] error getting challenge from database")
		return nil
	}
	return
}

func connect(server string) (success bool) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		fmt.Println("[!] failed to connect:", err.Error())
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("[+] connected!")
	challenge := make([]byte, 64)
	n, err := conn.Read(challenge)
	if err != nil {
		fmt.Println("[!] error getting challenge from server:",
			err.Error())
		return
	}
	challenge = challenge[:n]
	response := getResponse(server, challenge)
	if response == nil {
		fmt.Println("[!] challenge hasn't been seen yet")
		return
	}
	_, err = conn.Write(response)
	if err != nil {
		fmt.Println("[!] failed to send response:", err.Error())
		return
	}

	response = make([]byte, 512)
	n, err = conn.Read(response)
	if err != nil {
		fmt.Println("[!] failed to receive response from server:", err.Error())
	}
	response = response[:n]
	if errRegexp.Match(response) {
		fmt.Printf("[!] %s\n", string(response))
	} else {
		fmt.Printf("[+] server response: %s\n", string(response))
	}
	return true
}

func spoof(server string) {
	for {
		if connect(server) {
			fmt.Println("[+] successfully connected to server")
			break
		}
		<-time.After(1 * time.Second)
	}
	close(shutdown)
}

func main() {
	flDB := flag.String("d", "", "database file")
	flag.Parse()

	if *flDB == "" {
		fmt.Println("[!] no database file specified! Select one with -d")
		os.Exit(1)
	} else {
		dbFile = *flDB
	}

	if flag.NArg() == 0 {
		fmt.Println("[!] no server specified!")
		os.Exit(1)
	}
	server := flag.Args()[0]
	shutdown = make(chan interface{}, 1)

	go spoof(server)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Kill, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sigc:
		fmt.Println("[+] kill received")
	case <-shutdown:
		fmt.Println("[+] finished")
	}
}
