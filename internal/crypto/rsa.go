package crypto

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"math/big"

	"github.com/xdars/tg-mtproto-cl/internal/helpers"
)

func RSAd(data []byte, key *rsa.PublicKey) []byte {

	d := big.NewInt(0).SetBytes(data)
	exp := big.NewInt(int64(key.E))

	c := big.NewInt(0).Exp(d, exp, key.N)

	res := make([]byte, 256)
	copy(res, c.Bytes())

	return res
}

func RSAFingerprint(key *rsa.PublicKey) []byte {
	bi := big.NewInt(0).SetInt64(int64(key.E))

	e := &helpers.Buffer{Ext: bytes.NewBuffer(nil)}

	e.WriteMessage(key.N.Bytes())
	e.WriteMessage(bi.Bytes())

	fp := sha1.New()

	fp.Write(e.Ext.Bytes())
	return []byte(fp.Sum(nil))[12:]
}
