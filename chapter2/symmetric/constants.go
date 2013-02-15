package symmetric

// constants for the symmetric cryptographic functions.

import (
	"crypto/aes"
	"fmt"
)

const BlockSize = aes.BlockSize
const KeySize = 32

var Cipher = aes.NewCipher

var (
	PaddingError  = fmt.Errorf("invalid padding")
	DegradedError = fmt.Errorf("package is in degraded mode")
	BadBlockError = fmt.Errorf("bad block")
)
