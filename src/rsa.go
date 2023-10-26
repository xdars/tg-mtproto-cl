package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"math/big"
)

func (wire *Wire) LoadKeys() {
	pbkf, _ := ioutil.ReadFile("tg_pk.pem")
	pbk, _ := pem.Decode(pbkf)
	key, _ := x509.ParsePKCS1PublicKey(pbk.Bytes)

	wire.key = key
}

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

	e := &Buffer{bytes.NewBuffer(nil)}

	e.WriteMessage(key.N.Bytes())
	e.WriteMessage(bi.Bytes())

	fp := sha1.New()

	fp.Write(e.Bytes())
	return []byte(fp.Sum(nil))[12:]
}
