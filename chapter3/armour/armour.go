package armour

import "fmt"
import "github.com/kisom/gocrypto/chapter2/symmetric"

const (
	KeySize         = symmetric.KeySize
	ModeBinary byte = 0
	ModeArmour byte = 'A'
)

var ErrInvalidKey = fmt.Errorf("invalid key")

// GenerateKey generates a key appropriate for AES256 encryption
// with a mode header. If armour is true, this will return a
// base64-encoded key.
func GenerateKey(armour bool) (key []byte, err error) {
	var mode byte
	if armour {
		key, err = AbsGenerateKey()
		mode = ModeArmour
	} else {
		key, err = symmetric.GenerateKey()
		mode = ModeBinary
	}

	if err == nil {
		tmpkey := make([]byte, 0)
		tmpkey = append(tmpkey, mode)
		tmpkey = append(tmpkey, key...)
		key = tmpkey
	}
	return
}

func ErrInvalidMode(mode byte) error {
	return fmt.Errorf("invalid header type %d", mode)
}

// stripKey removes the header and does any base64 decoding required to
// return the key in the requested format.
func stripKey(key []byte, armour bool) (out []byte, err error) {
	var mode = key[0]
	key = key[1:]

	switch mode {
	case ModeBinary:
		if armour {
			out = EncodeBase64(key)
		} else {
			out = key
		}
	case ModeArmour:
		if !armour {
			out, err = DecodeBase64(key)
			out = trim(out)
		} else {
			out = key
		}
	default:
		err = ErrInvalidMode(mode)
	}

	return
}

// Encrypt encrypts the plaintext with the key. If the armour flag
// is set to true, the plaintext will be base64'd.
func Encrypt(key, pt []byte, armour bool) (ct []byte, err error) {
        rawkey, err := stripKey(key, armour)
        if err != nil {
                return
        }

        var mode byte
        var out []byte
        if armour {
                mode = ModeArmour
                out, err = AbsEncrypt(rawkey, pt)
        } else {
                mode = ModeBinary
                out, err = symmetric.Encrypt(rawkey, pt)
        }
        ct = make([]byte, 0)
        ct = append(ct, mode)
        ct = append(ct, out...)
        return
}

// Decrypt decrypts the 
func Decrypt(key, ct []byte) (pt []byte, err error) {
        var mode = ct[0]
        var armour bool = (mode == ModeArmour)

        ct = ct[1:]
        key, err = stripKey(key, armour)
        if err != nil {
                return
        }

        if armour {
                pt, err = AbsDecrypt(key, ct)
        } else {
                pt, err = symmetric.Decrypt(key, ct)
        }
        return
}
