package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"
)

// Encrypt an io.Reader to an io.Writer
func EncryptReader(key []byte, r io.Reader, w io.Writer) (err error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	iv, err := GenerateIV()
	if err != nil {
		return
	}

	cbc := cipher.NewCBCEncrypter(c, iv)
	n, err := w.Write(iv)
	if err != nil {
		return
	} else if n != BlockSize {
		err = fmt.Errorf("failed to write the IV")
		return
	}

	for {
		var n int
		block := make([]byte, BlockSize)
		n, err = r.Read(block)
		if err != nil && err != io.EOF {
			return
		} else if n == 0 {
			err = nil
			break
		}

		block = block[0:n]
		if n < BlockSize {
			block, err = Pad(block)
			if err != nil {
				return
			}
		}

		ct := make([]byte, len(block))
		cbc.CryptBlocks(ct, block)
		n, err = w.Write(ct)
		if err != nil {
			return
		}
	}
	return
}

func DecryptReader(key []byte, r io.Reader, w io.Writer) (err error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	iv := make([]byte, BlockSize)
	n, err := r.Read(iv)
	if err != nil {
		return
	} else if n != BlockSize {
		err = fmt.Errorf("failed to read IV")
		return
	}

	cbc := cipher.NewCBCDecrypter(c, iv)
	for {
		block := make([]byte, BlockSize)
		n, err = r.Read(block)
		if err != nil && err != io.EOF {
			return
		} else if n == 0 {
			break
		} else if n != BlockSize {
			err = BadBlockError
			return
		}

		pt := make([]byte, BlockSize)
		cbc.CryptBlocks(pt, block)

		pt, err = unpadBlock(pt)
		if err != nil {
			return
		}
		if _, err = w.Write(pt); err != nil {
			return
		}
	}
	if err == io.EOF {
		err = nil
	}
	return
}

// Encrypt a file.
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

func DecryptFile(in, out string, key []byte) (err error) {
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

	err = DecryptReader(key, inFile, outFile)
	return
}

func unpadBlock(p []byte) (m []byte, err error) {
	var pLen int
	origLen := len(p)

	if p[origLen-1] != 0x0 && p[origLen-1] != 0x80 {
		m = make([]byte, origLen)
		copy(m, p)
		return
	}
	for pLen = origLen - 1; pLen >= 0; pLen-- {
		if p[pLen] == 0x80 {
			break
		}

		if p[pLen] != 0x0 {
			break
		}

		if (p[pLen] != 0x0 && p[pLen] != 0x80) ||
			((origLen - pLen) > BlockSize) {
			err = PaddingError
			return
		}
	}

	m = make([]byte, pLen)
	copy(m, p)
	return
}
