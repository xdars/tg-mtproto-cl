package main

import (
	"math/big"
	"encoding/binary"
	"crypto/rand"
)

func Nonce() []byte {
	var max *big.Int = big.NewInt(0).Exp(big.NewInt(26), big.NewInt(26), nil)
	n, _ := rand.Int(rand.Reader, max)

	i := &Int128{Int: big.NewInt(0)}
	i.SetBytes(n.Bytes())
	return i.Bytes()
}

func NewNonce() []byte {
	var max *big.Int = big.NewInt(0).Exp(big.NewInt(46), big.NewInt(46), nil)
	n, _ := rand.Int(rand.Reader, max)

	i := &Int128{Int: big.NewInt(0)}
	i.SetBytes(n.Bytes())
	return i.Bytes()
}

func (pl *Buffer) PutLong(val int64) {
	arbitrary := make([]byte, 8)
	binary.LittleEndian.PutUint64(arbitrary, uint64(val))
	pl.Write(arbitrary)
}

func (pl *Buffer) PutUint64(val uint64) {
	arbitrary := make([]byte, 8)
	binary.LittleEndian.PutUint64(arbitrary, uint64(val))
	pl.Write(arbitrary)
}

func (pl *Buffer) PutInt128(val int64) {
	arb := make([]byte, 16)
	binary.LittleEndian.PutUint64(arb, uint64(val))
	pl.Write(arb)
}

func (pl *Buffer) PutInt(val uint32) {
	arb := make([]byte, 4)
	binary.LittleEndian.PutUint32(arb, val)
	pl.Write(arb)
}

/*
	If L <= 253, the serialization contains one byte with the value of L,
		then L bytes of the string followed by 0 to 3 characters containing 0,
			such that the overall length of the value be divisible by 4,
				whereupon all of this is interpreted as a sequence of int(L/4)+1 32-bit numbers.

	If L >= 254, the serialization contains byte 254, followed by 3 bytes with the string length L,
		followed by L bytes of the string, further followed by 0 to 3 null padding bytes.
*/

func (e *Buffer) WriteMessage(msg []byte) {
	lengthWithPaddingBytes := ((len(msg) / 4) + 1) * 4

	buf := make([]byte, lengthWithPaddingBytes)
	if len(msg) > 0xfe {
		buf[0] = byte(0xfe)
		buf[1] = byte(uint32(len(msg)))
		buf[2] = byte(uint32(len(msg)) >> 8)
		buf[3] = byte(uint32(len(msg)) >> 16)

		copy(buf[4:], msg)

	} else {
		buf[0] = byte(len(msg))
		copy(buf[1:], msg)
	}

	e.Write(buf)
}
