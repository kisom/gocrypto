package armour

import (
        "github.com/kisom/gocrypto/chapter2/symmetric"
)

// AbsGenerateKey generates a base64-encoded key.
func AbsGenerateKey() (key []byte, err error) {
        rawkey, err := symmetric.GenerateKey()
        if err != nil {
                return
        }

        key = EncodeBase64(rawkey)
        return
}

func AbsEncrypt(key []byte, pt []byte) (ct []byte, err error) {
        rawkey, err := Base64Decode(key)
        if err != nil {
                return
        }

        enc, err := symmetric.EncryptBytes(
}

func AbsDecrypt(key []byte, ct []byte) (pt []byte, err error) {

}
