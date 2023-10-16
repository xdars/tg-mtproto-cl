package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

const (
	MTPROTO_SERVER = "149.154.167.50:443"
	_sk0           = 1
	_sk1           = 4
)

var CRCS = map[string]uint32{
	"SEND_CODE":          0xa677244f,
	"REQ_PC":             0xbe7e8ef1,
	"REQ_DH":             0xd712e4be,
	"RES_PQ":             0x05162463,
	"INNER_DP":           0x83c95aec,
	"ServerDHParamsOK":   0xd0e8075c,
	"ServerDHInnterData": 0xb5890dba,
}

type Int128 struct {
	*big.Int
}

type Buffer struct {
	*bytes.Buffer
}

type Wire struct {
	intermediate bool
	mode         string
	pad          int
	N            *Net
	clNonce      []byte // resPQ stage
	srvNonce     []byte // resPQ stage
	newNonce     []byte // resPQ stage
	resPQStream  []byte
	key          *rsa.PublicKey
	resPQStage   bool
	resPQSent    bool
}

type Net struct {
	net.Conn
}

var resp chan []byte
var dataSentSignal chan bool

func (wire *Wire) Processor(w *sync.WaitGroup) {
	w.Add(1)
	go func() {
		for {

			select {
			case data := <-resp:
				wire.processResponse(data)
			}
		}
	}()
}

func (wire *Wire) Try(stream []byte, skip int) bool {
	padded := stream[skip:]
	if binary.LittleEndian.Uint32(padded[20:24]) == CRCS["ServerDHParamsOK"] {
		fmt.Println("[*] server_DH_params_ok")
		wire.ProcessServerDHParamsOk(padded, wire.newNonce, wire.resPQStream[40:56])
		return true
	}
	if binary.LittleEndian.Uint32(padded[20:24]) == CRCS["RES_PQ"] {
		fmt.Println("RES_PQ")
		wire.ProcessResPQ(padded, wire.clNonce)
		return true
	}
	return false
}

func (wire *Wire) processResponse(data []byte) {
	maxPad := 5

	for maxPad > 0 {
		ok := wire.Try(data, maxPad)
		if ok {
			break
		}
		maxPad--
	}
}
func (wire *Wire) DefineMode() {
	bytes := []byte{0xef}
	wire.pad = 1
	wire.mode = "abridged"
	if wire.intermediate {
		wire.mode = "intermediate"
		wire.pad = 4
		bytes = []byte{0xee, 0xee, 0xee, 0xee}
	}

	fmt.Println(bytes)
	wire.N.Write(bytes)
}

func (wire *Wire) makeAuthKey() {
	nonce := Nonce()
	wire.clNonce = nonce

	pl := ReqPCPayload(wire.clNonce)

	wire.Gift(pl)
}

func (wire *Wire) ProcessServerDHParamsOk(data []byte, nonceSecond, nonceServer []byte) {
	wire.resPQStage = false

	encryptedAnswer := data[56:]
	key, iv := genTmpKeys(nonceSecond, nonceServer)

	// does not work
	decryptedAnswer := AesDecrypt(key, iv, encryptedAnswer)
	_ = decryptedAnswer
}

func (wire *Wire) ProcessResPQ(data []byte, nonce []byte) {
	/*
		56-68
		Single-byte prefix denoting length, 8-byte string, and three bytes of padding
	*/
	pq := big.NewInt(0).SetBytes(data[57:65])
	a := Brent(big.NewInt(0).SetBytes(data[57:65]), 30, 1)
	p := a[0].Bytes()
	q := a[1].Bytes()
	fmt.Println(binary.LittleEndian.Uint32(p), binary.LittleEndian.Uint32(q))

	sha1h := sha1.New()
	newNonce := NewNonce()

	wire.newNonce = newNonce
	wire.srvNonce = data[40:56]

	innerDataPL := InnerDataPayload(pq.Bytes(), p, q, nonce, data[40:56], newNonce)

	hashedMessage := make([]byte, 255)

	wire.resPQStream = data

	sha1h.Write(innerDataPL)
	copy(hashedMessage, append(sha1h.Sum(nil), innerDataPL...))

	encrypted := RSAd(hashedMessage, wire.key)

	fmt.Println("Encrypted data length:", len(encrypted))
	keyFingerprint := int64(binary.LittleEndian.Uint64(RSAFingerprint(wire.key)))

	reqDH := reqDHPayload(nonce, data[40:56], p, q, keyFingerprint, encrypted)

	wire.Gift(reqDH)
}

func reqDHPayload(nonce []byte, nonceServer []byte, p []byte, q []byte, kfp int64, encrypted []byte) []byte {
	fmt.Println("[*] building req_dh_params payload")
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

	fmt.Println("[*] building req_pc_multi payload")

	payload.PutInt(CRCS["REQ_PC"])
	payload.Write(nonce)
	payload.Build()

	return payload.Bytes()
}

func main() {
	tcpServer, err := net.ResolveTCPAddr("tcp", MTPROTO_SERVER)
	if err != nil {
		fmt.Println("err", err)
		return
	}
	var wg sync.WaitGroup
	conn, err := net.DialTCP("tcp", nil, tcpServer)
	if err != nil {
		fmt.Println("err", err)
		return
	}
	resp = make(chan []byte, 5)
	dataSentSignal = make(chan bool, 5)

	wire := new(Wire)
	wire.LoadKeys()

	wire.N = &Net{conn}
	wire.Processor(&wg)

	wire.DefineMode()

	wire.makeAuthKey()
	wg.Wait()
}

func (wire *Wire) Gift(data []byte) {
	datalen := len(data) / 4
	var msglen []byte
	var payload []byte
	if !wire.intermediate {
		if datalen < int(0x7f) {
			msglen = append(msglen, byte(datalen))
		} else {
			b1 := byte(datalen)
			b2 := byte(datalen >> 8)
			b3 := byte(datalen >> 16)

			msglen = []byte{0x7f, b1, b2, b3}
		}
		payload = msglen
	} else {
		msglen = make([]byte, 4)
		binary.LittleEndian.PutUint32(msglen, uint32(len(data)))
		payload = msglen
	}
	payload = append(payload, data...)

	if _, err := wire.N.Write(payload); err != nil {
		fmt.Println("[x] could not send payload", err)
		return
	}
	rbuf := make([]byte, 1024)
	n, _ := wire.N.Read(rbuf)
	resp <- rbuf[:n]
	fmt.Printf("[+][m:%s][l:%d] payload sent;\nH: %s\n", wire.mode, len(payload), hex.EncodeToString(payload))

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
