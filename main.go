package main 

import "fmt"
import "encoding/hex"
import "net"
import "math/big"
import "bytes"
import "encoding/binary"
import "crypto/rand"
import "time"

const (
	MTPROTO_SERVER = "149.154.167.40:443"
	SEND_CODE = 0xa677244f
	REQ_PC = 0xbe7e8ef1
)

type Int128 struct {
	*big.Int
}
type Buffer struct {
	*bytes.Buffer
}
type Net struct {
	net.Conn
}
type Message struct {
	Msg []byte
	MsgID int64
}

/* 
	This simply returns a set of bytes needed for req_pc_multi
	(rewrite)
	First, write *function address*, then generate nonce:
		auth_key_id = 0
		message_id = exact unixtime * 2^32
		message_length = msgLen
		(length here is the length of the payload prior to writing the header: REQ_PC + nonce)
		message = msg = REQ_PC + nonce
*/

func ReqPCPayload() []byte {
	nonce := Nonce()
	payload := &Buffer{bytes.NewBuffer(nil)}

	payload.PutInt(REQ_PC)
	fmt.Println("[*] building req_pc_milti payload")	
	payload.Write(Nonce())
	
	msgLen := len(payload.Bytes())
	msg := make([]byte, msgLen)

	copy(msg, payload.Bytes())

	ts := time.Now().UnixNano() * 2 

	payload.Reset()

	payload.PutLong(0)
	payload.PutLong(ts^2) // Exact unixtime * 2^32
	payload.PutInt(uint32(msgLen))

	payload.Write(msg)

	fmt.Println("Nonce:", nonce)
	fmt.Println("Length:", msgLen)
	fmt.Println("Final set of bytes:", payload.Bytes())

	hexed := hex.EncodeToString(payload.Bytes())
	fmt.Println("Hex:", hexed)

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
	net := &Net{conn}

	initial, err := conn.Write([]byte{0xef})
	fmt.Println("Sent", initial, "bytes")

	pl := ReqPCPayload()

	net.Gift(pl)
	
}

func (net *Net) Gift(data []byte) {
	datalen := len(data) / 4
	var msglen []byte

	if datalen < int(0x7f) {
		msglen = append(msglen, byte(datalen))
	}

	// Send length
	if _, err := net.Write(msglen); err != nil {
		fmt.Println("[x] could not send message length", err)
		return
	}
	fmt.Println("[+] message length sent")

	// Send payload
	if _, err := net.Write(data); err != nil {
		fmt.Println("[x] could not send payload", err)
		return
	}
	fmt.Println("[+] payload sent")

	rbuf := make([]byte, 50)
	n, err := net.Read(rbuf)

	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("[+] Got response:", n)
	fmt.Println(rbuf)
	hexed := hex.EncodeToString(rbuf)
	fmt.Println("Hex:", hexed)
}

func Nonce() []byte {
	var max *big.Int = big.NewInt(0).Exp(big.NewInt(26), big.NewInt(26), nil)
	n, _ := rand.Int(rand.Reader, max)
	
	i := &Int128{Int: big.NewInt(0)}
	i.SetBytes(n.Bytes())
	return i.Bytes()
}

func (pl *Buffer) PutLong(val int64) {
	arbitrary := make([]byte, 8)
	binary.LittleEndian.PutUint64(arbitrary, uint64(0))
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