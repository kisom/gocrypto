package main

import (
        "bufio"
        "flag"
        "fmt"
        "net"
        "os"
        "regexp"
        "strings"
)

var password string
var errRegexp = regexp.MustCompile("^error: (.+)$")

func readPrompt(prompt string) (input string, err error) {
        fmt.Printf(prompt)
        rd := bufio.NewReader(os.Stdin)
        line, err := rd.ReadString('\n')
        if err != nil {
                return
        }
        input = strings.TrimSpace(line)
        return
}

func main() {
        var err error

        fAddress := flag.String("a", ":4141", "server address")
        flag.Parse()
        password, err = readPrompt("password: ")
        if err != nil {
                fmt.Println("[!] couldn't read password:", err.Error())
                os.Exit(1)
        }
        connect(*fAddress)
}

func connect(address string) {
        conn, err := net.Dial("tcp", address)
        if err != nil {
                fmt.Println("[!] failed to connect:", err.Error())
                os.Exit(1)
        }

        fmt.Println("[+] connected!")
        challenge := make([]byte, 64)
        n, err := conn.Read(challenge)
        if err != nil {
                fmt.Println("[!] error getting challenge from server:", err.Error())
                os.Exit(1)
        }
        challenge = challenge[:n]
        responseStr := fmt.Sprintf("%s%s", password, string(challenge))
        response := hash(responseStr)
        _, err = conn.Write(response)
        if err != nil {
                fmt.Println("[!] failed to send response:", err.Error())
                os.Exit(1)
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
}

