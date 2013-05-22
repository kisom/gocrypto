package authsym

// constants for the symmetric cryptographic functions.

import (
	"crypto/aes"
	"fmt"
)

const BlockSize = aes.BlockSize
const KeySize = 32

var (
	PaddingError        = fmt.Errorf("invalid padding")
	DegradedError       = fmt.Errorf("package is in degraded mode")
	BadBlockError       = fmt.Errorf("bad block")
	IVSizeMismatchError = fmt.Errorf("IV not the proper length")
	WriteError          = fmt.Errorf("write error")
)
