package hybrid

// constants for the symmetric cryptographic functions.

import (
	"crypto/aes"
	"fmt"
)

const BlockSize = aes.BlockSize

var (
	PaddingError        = fmt.Errorf("invalid padding")
	DegradedError       = fmt.Errorf("package is in degraded mode")
	BadBlockError       = fmt.Errorf("bad block")
	IVSizeMismatchError = fmt.Errorf("IV not the proper length")
	WriteError          = fmt.Errorf("write error")
)
