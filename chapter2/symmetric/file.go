package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
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

	n, err := w.Write(iv)
	if err != nil {
		return
	} else if n != BlockSize {
		err = IVSizeMismatchError
		return
	}

	cbc := cipher.NewCBCEncrypter(c, iv)

	// We use a cryptoBlock to differentiate between partial reads and
	// EOF conditions.
	cryptBlock := make([]byte, 0)

	for {
		if len(cryptBlock) == BlockSize {
			cbc.CryptBlocks(cryptBlock, cryptBlock)
			n, err = w.Write(cryptBlock)
			if err != nil {
				return
			} else if n != BlockSize {
				err = BlockSizeMismatchError
				return
			}
			Zeroise(&cryptBlock)
		}

		readLen := BlockSize - len(cryptBlock)
		buf := make([]byte, readLen)
		n, err = r.Read(buf)
		if err != nil && err != io.EOF {
			return
		} else if n > 0 {
			cryptBlock = append(cryptBlock, buf[0:n]...)
		}

		if err != nil && err == io.EOF {
			err = nil
			break
		}
	}

	cryptBlock, err = Pad(cryptBlock)
	if err != nil {
		return
	} else if (len(cryptBlock) % BlockSize) != 0 {
		err = BlockSizeMismatchError
		return
	}
	cbc.CryptBlocks(cryptBlock, cryptBlock)
	n, err = w.Write(cryptBlock)
	if err != nil {
		return
	} else if n != BlockSize {
		err = BlockSizeMismatchError
	}
	return
}

// Decrypt an io.Reader to an io.Writer.
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
		err = IVSizeMismatchError
		return
	}

	cbc := cipher.NewCBCDecrypter(c, iv)

	// We use a cryptoBlock to differentiate between partial reads and EOF conditions.
	cryptBlock := make([]byte, 0)

	for {
		if len(cryptBlock) == BlockSize {
			cbc.CryptBlocks(cryptBlock, cryptBlock)
			cryptBlock, err = unpadBlock(cryptBlock)
			if err != nil {
				return
			}
			n, err = w.Write(cryptBlock)
			if err != nil {
				return
			}
			Zeroise(&cryptBlock)
		}

		readLen := BlockSize - len(cryptBlock)
		buf := make([]byte, readLen)
		n, err = r.Read(buf)
		if err != nil && err != io.EOF {
			return
		} else if n > 0 {
			cryptBlock = append(cryptBlock, buf[0:n]...)
		}

		if err != nil && err == io.EOF {
			err = nil
			break
		}
	}

	if len(cryptBlock) > 0 {
		cryptBlock, err = Unpad(cryptBlock)
		if err != nil {
			return
		}

		cbc.CryptBlocks(cryptBlock, cryptBlock)
		n, err = w.Write(cryptBlock)
		if err != nil {
			return
		} else if n != BlockSize {
			err = BlockSizeMismatchError
		}
	}
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
