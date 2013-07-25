package pks

import "fmt"
import "testing"

var (
	testkeychain *KeyChain
	testkcsig []byte
	testkcmsg = []byte("Hello, world.")
)

func TestSign(t *testing.T) {
	var err error
	testkeychain, err = ImportKeyChain("testdata/sample.pem")
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	testkcsig, err = Sign(testkeychain.Private, testkcmsg)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	err = Verify(&testkeychain.Private.PublicKey, testkcmsg, testkcsig)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
}
