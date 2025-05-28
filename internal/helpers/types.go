package helpers

import (
	"math/big"
	"bytes"
)
type Int128 struct {
	*big.Int
}

type Buffer struct {
	*bytes.Buffer
}