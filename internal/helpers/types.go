package helpers

import (
	"bytes"
	"math/big"
)

type Int128 struct {
	*big.Int
}

type Buffer struct {
	Ext *bytes.Buffer
}
