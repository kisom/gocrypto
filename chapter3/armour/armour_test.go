package armour

import "bytes"
import "fmt"
import "testing"

// FailWithError is a utility for dumping errors and failing the test.
func FailWithError(t *testing.T, err error) {
	fmt.Println("failed")
	if err != nil {
		fmt.Println("[!] ", err.Error())
	}
	t.FailNow()
}

func TestGenerateKey(t *testing.T) {
	fmt.Printf("ArmourGenerateKey: ")
	binkey, err := GenerateKey(true)
	if err != nil {
		FailWithError(t, err)
	} else if outkey, err := stripKey(binkey, false); err != nil {
		FailWithError(t, err)
	} else if len(outkey) != KeySize {
		msg := fmt.Sprintf("expected len=%d, len=%d", KeySize,
			len(outkey))
		err = fmt.Errorf("invalid key\n\t%s", msg)
		FailWithError(t, err)
	}

	enckey, err := GenerateKey(false)
	if err != nil {
		FailWithError(t, err)
	} else if outkey, err := stripKey(enckey, false); err != nil {
		FailWithError(t, err)
	} else if len(outkey) != KeySize {
		msg := fmt.Sprintf("expected len=%d, len=%d", KeySize,
			len(outkey))
		err = fmt.Errorf("invalid key\n\t%s", msg)
		FailWithError(t, err)
	}
	fmt.Println("ok")
}

func TestEncryptDecryptArmour(t *testing.T) {
	fmt.Printf("ArmourEncryption: ")

	testVector := []byte("Hello, gophers. This is a test message.")
	key, err := GenerateKey(true)
	if err != nil {
		FailWithError(t, err)
	}

	enc, err := Encrypt(key, testVector, true)
	if err != nil {
		FailWithError(t, err)
	}
	origenc := make([]byte, len(enc))
	copy(origenc, enc)

	dec, err := Decrypt(key, enc)
	if err != nil {
		FailWithError(t, err)
	}

	if !bytes.Equal(testVector, dec) {
		FailWithError(t, ErrNoMatch)
	} else if !bytes.Equal(enc, origenc) {
		FailWithError(t, fmt.Errorf("ct was modified"))
	}
	fmt.Println("ok")
}

func TestEncryptDecryptBinary(t *testing.T) {
	fmt.Printf("BinaryEncryption: ")

	testVector := []byte("Hello, gophers. This is a test message.")
	key, err := GenerateKey(false)
	if err != nil {
		FailWithError(t, err)
	}

	enc, err := Encrypt(key, testVector, false)
	if err != nil {
		FailWithError(t, err)
	}
	origenc := make([]byte, len(enc))
	copy(origenc, enc)

	dec, err := Decrypt(key, enc)
	if err != nil {
		FailWithError(t, err)
	}

	if !bytes.Equal(testVector, dec) {
		FailWithError(t, ErrNoMatch)
	} else if !bytes.Equal(enc, origenc) {
		FailWithError(t, fmt.Errorf("ct was modified"))
	}
	fmt.Println("ok")
}

func TestEncryptDecryptArmourWithBinaryKey(t *testing.T) {
	fmt.Printf("ArmourEncryption (binary key): ")

	testVector := []byte("Hello, gophers. This is a test message.")
	key, err := GenerateKey(false)
	if err != nil {
		FailWithError(t, err)
	}

	enc, err := Encrypt(key, testVector, true)
	if err != nil {
		FailWithError(t, err)
	}
	origenc := make([]byte, len(enc))
	copy(origenc, enc)

	dec, err := Decrypt(key, enc)
	if err != nil {
		FailWithError(t, err)
	}

	if !bytes.Equal(testVector, dec) {
		FailWithError(t, ErrNoMatch)
	} else if !bytes.Equal(enc, origenc) {
		FailWithError(t, fmt.Errorf("ct was modified"))
	}
	fmt.Println("ok")
}

func TestEncryptDecryptBinaryWithArmouredKey(t *testing.T) {
	fmt.Printf("BinaryEncryption (armoured key): ")

	testVector := []byte("Hello, gophers. This is a test message.")
	key, err := GenerateKey(true)
	if err != nil {
		FailWithError(t, err)
	}

	enc, err := Encrypt(key, testVector, false)
	if err != nil {
		FailWithError(t, err)
	}
	origenc := make([]byte, len(enc))
	copy(origenc, enc)

	dec, err := Decrypt(key, enc)
	if err != nil {
		FailWithError(t, err)
	}

	if !bytes.Equal(testVector, dec) {
		FailWithError(t, ErrNoMatch)
	} else if !bytes.Equal(enc, origenc) {
		FailWithError(t, fmt.Errorf("ct was modified"))
	}
	fmt.Println("ok")
}
