package wire

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/xdars/tg-mtproto-cl/internal/crypto"
	"github.com/xdars/tg-mtproto-cl/internal/helpers"
	"github.com/xdars/tg-mtproto-cl/internal/mtproto"
	"github.com/xdars/tg-mtproto-cl/internal/payload"
	"log"
	"math/big"
	"sync"
)

func (wire *Wire) DefineMode() {
	bytes := []byte{0xef}
	wire.Pad = 1
	wire.Mode = "abridged"
	if wire.Intermediate {
		wire.Mode = "intermediate"
		wire.Pad = 4
		bytes = []byte{0xee, 0xee, 0xee, 0xee}
	}

	wire.N.C.Write(bytes)
}

func (wire *Wire) MakeAuthKey() {
	nonce := helpers.Nonce()
	wire.ClNonce = nonce

	pl := payload.ReqPCPayload(wire.ClNonce)

	wire.Gift(pl)
}

func (wire *Wire) Processor(ctx context.Context, w *sync.WaitGroup) {
	w.Add(1)
	go func() {
		for {

			select {
			case data := <-Resp:
				wire.ProcessResponse(ctx, data)
			}
		}
	}()
}

func (wire *Wire) Try(debounce func(f func()), stream []byte, skip int) bool {
	padded := stream[skip:]
	if binary.LittleEndian.Uint32(padded[20:24]) == payload.CRCS["ServerDHParamsOK"] {
		log.Println("[*] server_DH_params_ok")
		wire.ProcessServerDHParamsOk(padded, wire.NewNonce, wire.ResPQStream[40:56])
		return true
	}
	if binary.LittleEndian.Uint32(padded[20:24]) == payload.CRCS["RES_PQ"] {
		log.Println("RES_PQ")
		wire.ProcessResPQ(padded, wire.ClNonce)
		return true
	}
	if len(stream) == 5 {
		debounce(func() {
			log.Println(fmt.Sprintf("no matches found. data is %d len, tried to skip %d bytes", len(stream), skip))
			log.Println("retrying: making auth key again")
			wire.MakeAuthKey()
		})
	}
	return false
}

func (wire *Wire) ProcessResponse(ctx context.Context, data []byte) {
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

func (wire *Wire) ProcessServerDHParamsOk(data []byte, nonceSecond, nonceServer []byte) {

	encryptedAnswer := data[56:]
	key, iv := crypto.GenTmpKeys(nonceSecond, nonceServer)

	decryptedAnswer := crypto.AesDecrypt(key, iv, encryptedAnswer)
	_ = decryptedAnswer
	crc := binary.LittleEndian.Uint32(decryptedAnswer[:4])
	_ = crc
	log.Println(hex.EncodeToString(decryptedAnswer[4:8]))
}

func (wire *Wire) ProcessResPQ(data []byte, nonce []byte) {
	pq := big.NewInt(0).SetBytes(data[57:65])
	a := mtproto.Brent(big.NewInt(0).SetBytes(data[57:65]), 30, 1)

	p := a[0].Bytes()
	q := a[1].Bytes()

	sha1h := sha1.New()
	newNonce := helpers.NewNonce()

	wire.NewNonce = newNonce
	wire.SrvNonce = data[40:56]

	innerDataPL := payload.InnerDataPayload(pq.Bytes(), p, q, nonce, data[40:56], newNonce)

	hashedMessage := make([]byte, 255)

	wire.ResPQStream = data

	sha1h.Write(innerDataPL)
	copy(hashedMessage, append(sha1h.Sum(nil), innerDataPL...))

	encrypted := crypto.RSAd(hashedMessage, wire.Key)

	log.Println("Encrypted data length:", len(encrypted))
	keyFingerprint := int64(binary.LittleEndian.Uint64(crypto.RSAFingerprint(wire.Key)))

	reqDH := payload.ReqDHPayload(nonce, data[40:56], p, q, keyFingerprint, encrypted)

	wire.Gift(reqDH)
}

func (wire *Wire) Gift(data []byte) {
	datalen := len(data) / 4
	var msglen []byte
	var payload []byte
	if !wire.Intermediate {
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

	if _, err := wire.N.C.Write(payload); err != nil {
		log.Println("could not send payload", err)
		return
	}
	rbuf := make([]byte, 1024)
	n, _ := wire.N.C.Read(rbuf)
	Resp <- rbuf[:n]
	log.Printf("[m:%s][l:%d] payload sent\n", wire.Mode, len(payload))

}
