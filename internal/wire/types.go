package wire

import (
	"net"
	"crypto/rsa"
)

type Wire struct {
	Intermediate bool
	Mode         string
	Pad          int
	N            *Net
	ClNonce      []byte // resPQ stage
	SrvNonce     []byte // resPQ stage
	NewNonce     []byte // resPQ stage
	ResPQStream  []byte
	Key          *rsa.PublicKey
}

type Net struct {
	C net.Conn
}

var Resp chan []byte