package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"time"
)

const (
	MTPROTO_SERVER     = "149.154.167.50:443"
	SEND_CODE          = 0xa677244f
	REQ_PC             = 0xbe7e8ef1
	REQ_DH             = 0xd712e4be
	INNER_DP           = 0x83c95aec
	ServerDHParamsOK   = 0xd0e8075c
	ServerDHInnterData = 0xb5890dba

	_sk0 = 1
	_sk1 = 4
)

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
}

type Net struct {
	net.Conn
}

type Message struct {
	Msg   []byte
	MsgID int64
}

func AesDecrypt(key, iv, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	if len(data) < aes.BlockSize {
		fmt.Println("block size short")
		return nil
	}
	iv = data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	fmt.Println("Decrypted data length:", len(data))
	return data

}
func genTmpKeys(nonceSecond, nonceServer []byte) (key, iv []byte) {
	fmt.Println("Generating tmp keys")
	fmt.Println("newNonce", hex.EncodeToString(nonceSecond))
	fmt.Println("nonceServer", hex.EncodeToString(nonceServer))

	b0 := make([]byte, len(nonceSecond)+len(nonceServer))
	b1 := make([]byte, len(nonceSecond)+len(nonceServer))

	copy(b0[:len(nonceSecond)], nonceSecond)
	copy(b0[len(nonceSecond):], nonceServer)

	copy(b1[:len(nonceServer)], nonceServer)
	copy(b1[len(nonceServer):], nonceSecond)

	b0Hash := sha1.New()
	b1Hash := sha1.New()

	b0Hash.Write(b0)
	b1Hash.Write(b1)

	tmpAESKey := make([]byte, 32)
	copy(tmpAESKey[:len(b0Hash.Sum(nil))], b0Hash.Sum(nil))
	copy(tmpAESKey[len(b0Hash.Sum(nil)):], b1Hash.Sum(nil)[:12])

	fmt.Println("tmp_aes_key:", hex.EncodeToString(tmpAESKey))

	b2 := make([]byte, len(nonceSecond)*2)
	copy(b2[:len(nonceSecond)], nonceSecond)
	copy(b2[len(nonceSecond):], nonceSecond)

	b2Hash := sha1.New()
	b2Hash.Write(b2)

	tmpAESIV := make([]byte, 32)
	copy(tmpAESIV[0:], b1Hash.Sum(nil)[12:12+8])
	copy(tmpAESIV[8:], b2Hash.Sum(nil))
	copy(tmpAESIV[28:], nonceSecond[0:4])

	fmt.Println("tmp_aes_iv:", hex.EncodeToString(tmpAESIV), len(tmpAESIV))
	return tmpAESKey, tmpAESIV
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
	pl := ReqPCPayload(nonce)

	wire.Gift(pl)
	rbuf := make([]byte, 1024)
	n, _ := wire.N.Read(rbuf)
	wire.ProcessResPQ(rbuf[wire.pad:n], nonce)
}

func (wire *Wire) ProcessServerDHParamsOk(data []byte, nonceSecond, nonceServer []byte) {
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
	p, q := fct(pq.Int64())
	pn := binary.BigEndian.Uint32(p)
	qn := binary.BigEndian.Uint32(q)
	
	fmt.Println(p, q)
	fmt.Println(pn, qn)

	if pn > qn {
		fmt.Println("p is not less than q")
		return
	}
	sha1h := sha1.New()
	newNonce := NewNonce()

	innerDataPL := InnerDataPayload(pq.Bytes(), p, q, nonce, data[40:56], newNonce)
	hashedMessage := make([]byte, 255)

	sha1h.Write(innerDataPL)
	copy(hashedMessage, append(sha1h.Sum(nil), innerDataPL...))

	// perhaps needs to be taken away to different place
	pbkf, _ := ioutil.ReadFile("tg_pk.pem")
	pbk, _ := pem.Decode(pbkf)
	key, _ := x509.ParsePKCS1PublicKey(pbk.Bytes)

	// RSA it
	encrypted := RSAd(hashedMessage, key)
	// encrypted data length is important. *track* it
	fmt.Println("Encrypted data length:", len(encrypted))
	keyFingerprint := int64(binary.LittleEndian.Uint64(RSAFingerprint(key)))

	// slice is 16 bytes of the returned server_nonce
	reqDH := reqDHPayload(nonce, data[40:56], p, q, keyFingerprint, encrypted)

	wire.Gift(reqDH)

	rbuf := make([]byte, 1024)
	n2, _ := wire.N.Read(rbuf)
	rbuf = rbuf[_sk1:n2] // skip four bytes

	constructorNmb := binary.LittleEndian.Uint32(rbuf[20:24])
	if constructorNmb == ServerDHParamsOK {
		fmt.Println("[*] server_DH_params_ok")
		wire.ProcessServerDHParamsOk(rbuf, newNonce, data[40:56])
	}
}

func reqDHPayload(nonce []byte, nonceServer []byte, p []byte, q []byte, kfp int64, encrypted []byte) []byte {
	fmt.Println("[*] building req_dh_params payload")
	payload := &Buffer{bytes.NewBuffer(nil)}
	payload.PutInt(REQ_DH)
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

	payload.PutInt(INNER_DP)

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

	payload.PutInt(REQ_PC)
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

	conn, err := net.DialTCP("tcp", nil, tcpServer)
	if err != nil {
		fmt.Println("err", err)
		return
	}
	wire := &Wire{false, "", 0, &Net{conn}}
	wire.DefineMode()

	wire.makeAuthKey()
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
