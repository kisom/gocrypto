// gensymkey is a command line tool to generate symmetric keys and write them
// to a file.
package main

import (
        "flag"
        "fmt"
        "github.com/kisom/gocrypto/chapter2/symmetric"
        "io/ioutil"
        "os"
)

var KeyGenerator = symmetric.GenerateKey

func main() {
        longTerm := flag.Bool("lt", false, "generate long-term keys")
        flag.Parse()

        if flag.NArg() == 0 {
                flag.Usage()
                os.Exit(1)
        }

        if *longTerm {
                KeyGenerator = symmetric.GenerateLTKey
        }

        keyCount := 0
        fmt.Printf("[+] generating %d keys\n", flag.NArg())
        for i, keyFile := range flag.Args() {

                key, err := KeyGenerator()
                if err != nil {
                        fmt.Printf("[!] key #%d generation failed: \n", i)
                        fmt.Printf("    %s\n\n", err.Error())
                        continue
                }

                err = ioutil.WriteFile(keyFile, key, 0400)
                if err != nil {
                        fmt.Printf("[!] writing key #%d failed: \n", i)
                        fmt.Printf("    %s\n\n", err.Error())
                        continue

                }
                fmt.Printf(".")
                keyCount++

        }
        if keyCount > 0 {
                fmt.Printf("\n")
        }
        fmt.Printf("[+] generated %d keys\n", keyCount)
}
