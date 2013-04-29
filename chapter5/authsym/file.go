package authsym

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"os"
)

// Encrypt an io.Reader to an io.Writer
func encryptReader(key []byte, r io.Reader, w io.Writer) (err error) {
        iv, err := GenerateIV()
        if err != nil {
                return
        }

        aes, err := aes.NewCipher(key)
        if err != nil {
                return
        }

        ctr := cipher.NewCTR(aes, iv)
        buf := make([]byte, BlockSize)

        for {
                var rn int
                rn, err = r.Read(buf)
                if err != nil {
                        if err == io.EOF {
                                err = nil
                        }
                        return
                }

                ctr.XORKeyStream(buf[:rn], buf[:rn])
                _, err = w.Write(buf[:rn])
                if err != nil {
                        return
                }
        }
        return
}

// Decrypt an io.Reader to an io.Writer.
func decryptReader(key []byte, r io.Reader, w io.Writer) (err error) {
        return
}

// Encrypt the input file to the output file.
func EncryptFile(in, out string, key []byte) (err error) {
	inFile, err := os.Open(in)
	if err != nil {
		return
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	defer outFile.Close()

	err = EncryptReader(key, inFile, outFile)
	return
}

// Decrypt the input file to the output file.
func DecryptFile(in, out string, key []byte) (err error) {
	inFile, err := os.Open(in)
	if err != nil {
		return
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0600)
	if err != nil {
		return
	}
	defer outFile.Close()

	err = DecryptReader(key, inFile, outFile)
	return
}

