package hash

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

const testPass = "hello, world"

var refSalt = []byte{18, 211, 236, 123, 122, 192, 39, 255, 166, 138,
	192, 93, 76, 170, 60, 168, 221, 211, 121, 128, 156, 213, 252,
	129, 253, 241, 82, 42, 185, 33, 61, 84, 72, 56, 48, 193, 213,
	219, 27, 30, 171, 91, 177, 4, 98, 222, 42, 125, 29, 195, 251,
	205, 76, 62, 22, 129, 84, 95, 42, 8, 212, 55, 251, 229}
var refHash = []byte{43, 183, 196, 128, 139, 53, 134, 211, 2, 9, 97,
	242, 126, 85, 162, 162, 164, 72, 93, 182, 26, 200, 213, 193,
	199, 121, 200, 108, 198, 128, 179, 12}
var refPH = &PasswordKey{refHash, refSalt}

func TestHashPasswordWithSalt(t *testing.T) {
	fmt.Printf("[+] testing HashPasswordWithSalt: ")
	pk := DeriveKeyWithSalt(testPass, refSalt)
	if !bytes.Equal(pk.Key, refHash) {
		fmt.Println("failed")
		fmt.Println("[!] hashes do not match")
		t.FailNow()
	} else if !bytes.Equal(pk.Salt, refSalt) {
		fmt.Println("failed")
		fmt.Println("[!] salts do not match")
		t.FailNow()
	}
	fmt.Println("ok")
}

func TestMatchPassword(t *testing.T) {
	fmt.Printf("[+] testing MatchPassword (and HashPassword): ")
	pk := DeriveKey(testPass)
	if !MatchPassword(testPass, pk) {
		fmt.Println("failed")
		fmt.Println("[!] password match failed when it should have passed")
		t.FailNow()
	}
	fmt.Println("ok")
}

func TestEnsureFails(t *testing.T) {
	fmt.Printf("[+] ensuring authentication fails for wrong password: ")
	if MatchPassword("hello world", refPH) {
		fmt.Println("failed")
		fmt.Println("[!] authentication should not have succeeded!")
		t.FailNow()
	}
	fmt.Println("ok")
}

func TestEmptyPassFails(t *testing.T) {
	fmt.Printf("[+] ensuring empty password fails: ")
	if MatchPassword("", refPH) {
		fmt.Println("failed")
		fmt.Println("[!] authentication should not have succeeded!")
		t.FailNow()
	}
	fmt.Println("ok")
}

func BenchmarkHashPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		DeriveKey(testPass)
	}
}

func TestOneHashTime(t *testing.T) {
	fmt.Println("[+] testing time for one password check")
	start := time.Now()
	MatchPassword("goodbye world", refPH)
	stop := time.Now()
	spent := stop.Sub(start)
	fmt.Printf("[+] time spent: %s\n", spent.String())
}
