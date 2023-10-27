package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
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

func (wire *Wire) Processor(ctx context.Context, w *sync.WaitGroup) {
	w.Add(1)
	go func() {
		for {

			select {
			case data := <-resp:
				wire.processResponse(ctx, data)
			}
		}
	}()
}

func (wire *Wire) Try(debounce func(f func()), stream []byte, skip int) bool {
	padded := stream[skip:]
	if binary.LittleEndian.Uint32(padded[20:24]) == CRCS["ServerDHParamsOK"] {
		log.Println("[*] server_DH_params_ok")
		wire.ProcessServerDHParamsOk(padded, wire.newNonce, wire.resPQStream[40:56])
		return true
	}
	if binary.LittleEndian.Uint32(padded[20:24]) == CRCS["RES_PQ"] {
		log.Println("RES_PQ")
		wire.ProcessResPQ(padded, wire.clNonce)
		return true
	}
	if len(stream) == 5 {
		debounce(func() {
			log.Println(fmt.Sprintf("no matches found. data is %d len, tried to skip %d bytes", len(stream), skip))
			log.Println("retrying: making auth key again")
			wire.makeAuthKey()
		})
	}
	return false
}

func (wire *Wire) processResponse(ctx context.Context, data []byte) {
	maxPad := 5
	debounce := ctx.Value("debounce")
	for maxPad > 0 {
		ok := wire.Try(debounce.(func(f func())), data, maxPad)
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

	log.Println(bytes)
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
	crc := binary.LittleEndian.Uint32(decryptedAnswer[:4])
	_ = crc
	log.Println(hex.EncodeToString(decryptedAnswer[4:8]))
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
	log.Println(binary.LittleEndian.Uint32(p), binary.LittleEndian.Uint32(q))

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

	log.Println("Encrypted data length:", len(encrypted))
	keyFingerprint := int64(binary.LittleEndian.Uint64(RSAFingerprint(wire.key)))

	reqDH := reqDHPayload(nonce, data[40:56], p, q, keyFingerprint, encrypted)

	wire.Gift(reqDH)
}

func main() {

	ctx := context.TODO()

	debounce := Register(100 * time.Millisecond)
	ctx = context.WithValue(ctx, "debounce", debounce)
	tcpServer, err := net.ResolveTCPAddr("tcp", MTPROTO_SERVER)
	if err != nil {
		log.Println("err", err)
		return
	}
	var wg sync.WaitGroup
	conn, err := net.DialTCP("tcp", nil, tcpServer)
	if err != nil {
		log.Println("err", err)
		return
	}
	resp = make(chan []byte, 5)

	wire := new(Wire)
	wire.LoadKeys()
	if wire.key == nil { return }
	wire.N = &Net{conn}
	wire.Processor(ctx, &wg)

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
		log.Println("[x] could not send payload", err)
		return
	}
	rbuf := make([]byte, 1024)
	n, _ := wire.N.Read(rbuf)
	resp <- rbuf[:n]
	log.Printf("[+][m:%s][l:%d] payload sent;\nH: %s\n", wire.mode, len(payload), hex.EncodeToString(payload))

}
