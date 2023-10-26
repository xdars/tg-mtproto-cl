package main

import (
	"bytes"
	"log"
	"time"
)

func reqDHPayload(nonce []byte, nonceServer []byte, p []byte, q []byte, kfp int64, encrypted []byte) []byte {
	log.Println("[*] building req_dh_params payload")
	payload := &Buffer{bytes.NewBuffer(nil)}
	payload.PutInt(CRCS["REQ_DH"])
	payload.Write(nonce)
	payload.Write(nonceServer)
	payload.WriteMessage(p)
	payload.WriteMessage(q)
	payload.PutLong(kfp)
	payload.WriteMessage(encrypted)

	payload.Build()

	return payload.Bytes()
}

func InnerDataPayload(pq, p, q, nonce, serverNonce, NewNonce []byte) []byte {
	payload := &Buffer{bytes.NewBuffer(nil)}

	payload.PutInt(CRCS["INNER_DP"])

	payload.WriteMessage(pq)
	payload.WriteMessage(p)
	payload.WriteMessage(q)

	payload.Write(nonce)
	payload.Write(serverNonce)
	payload.Write(NewNonce)

	return payload.Bytes()
}

func ReqPCPayload(nonce []byte) []byte {
	payload := &Buffer{bytes.NewBuffer(nil)}

	log.Println("[*] building req_pc_multi payload")

	payload.PutInt(CRCS["REQ_PC"])
	payload.Write(nonce)
	payload.Build()

	return payload.Bytes()
}

func (p *Buffer) Build() {
	_len := len(p.Bytes())
	_tmp := make([]byte, _len)
	copy(_tmp, p.Bytes())

	_ts := (time.Now().UnixNano() * 2) ^ 2

	p.Reset()

	p.PutLong(0)
	p.PutLong(_ts)
	p.PutInt(uint32(_len))

	p.Write(_tmp)
}
