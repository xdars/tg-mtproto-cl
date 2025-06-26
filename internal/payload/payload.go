package payload

import (
	"bytes"
	"log"
	"time"
	"github.com/xdars/tg-mtproto-cl/internal/helpers"
)
type buf helpers.Buffer

var CRCS = map[string]uint32{
	"SEND_CODE":          0xa677244f,
	"REQ_PC":             0xbe7e8ef1,
	"REQ_DH":             0xd712e4be,
	"RES_PQ":             0x05162463,
	"INNER_DP":           0x83c95aec,
	"ServerDHParamsOK":   0xd0e8075c,
	"ServerDHInnterData": 0xb5890dba,
}

func ReqDHPayload(nonce []byte, nonceServer []byte, p []byte, q []byte, kfp int64, encrypted []byte) []byte {
	log.Println("[*] building req_dh_params payload")
	payload := &helpers.Buffer{Ext: bytes.NewBuffer(nil)}
	payload.PutInt(CRCS["REQ_DH"])
	payload.Ext.Write(nonce)
	payload.Ext.Write(nonceServer)
	payload.WriteMessage(p)
	payload.WriteMessage(q)
	payload.PutLong(kfp)
	payload.WriteMessage(encrypted)

	Build(payload)

	return payload.Ext.Bytes()
}

func InnerDataPayload(pq, p, q, nonce, serverNonce, NewNonce []byte) []byte {
	payload := &helpers.Buffer{Ext: bytes.NewBuffer(nil)}

	payload.PutInt(CRCS["INNER_DP"])

	payload.WriteMessage(pq)
	payload.WriteMessage(p)
	payload.WriteMessage(q)

	payload.Ext.Write(nonce)
	payload.Ext.Write(serverNonce)
	payload.Ext.Write(NewNonce)

	return payload.Ext.Bytes()
}

func ReqPCPayload(nonce []byte) []byte {
	payload := &helpers.Buffer{Ext: bytes.NewBuffer(nil)}

	log.Println("[*] building req_pc_multi payload")

	payload.PutInt(CRCS["REQ_PC"])
	payload.Ext.Write(nonce)
	Build(payload)

	return payload.Ext.Bytes()
}

func Build(p *helpers.Buffer) {
	_len := len(p.Ext.Bytes())
	_tmp := make([]byte, _len)
	copy(_tmp, p.Ext.Bytes())

	_ts := (time.Now().UnixNano() * 2) ^ 2

	p.Ext.Reset()

	p.PutLong(0)
	p.PutLong(_ts)
	p.PutInt(uint32(_len))

	p.Ext.Write(_tmp)
}
