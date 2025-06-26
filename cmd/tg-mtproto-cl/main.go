package main

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
	"github.com/xdars/tg-mtproto-cl/internal/wire"
	"github.com/xdars/tg-mtproto-cl/internal/debouncer"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

const (
	MTPROTO_SERVER = "149.154.167.50:443"
	_sk0           = 1
	_sk1           = 4
)

type Wire struct {
	*wire.Wire
}

func LoadKeys(wire *wire.Wire) {
	pbkf, err := ioutil.ReadFile("tg_pk.pem")
	if err != nil {
		log.Println(err)
		return
	}
	pbk, _ := pem.Decode(pbkf)
	key, _ := x509.ParsePKCS1PublicKey(pbk.Bytes)

	wire.Key = key
}

func main() {

	ctx := context.TODO()

	debounce := debouncer.Register(100 * time.Millisecond)
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
	wire.Resp = make(chan []byte, 5)

	w := new(wire.Wire)
	
	LoadKeys(w)
	if w.Key == nil {
		return
	}
	w.N = &wire.Net{C:conn}
	w.Processor(ctx, &wg)

	w.DefineMode()

	w.MakeAuthKey()
	wg.Wait()
}