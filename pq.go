package main

import (
	"encoding/binary"
	"fmt"
)

func g(x, p int64) int64 {
	return (x*x + 1) % p
}

func gcd(x, y int64) int64 {
	for y != 0 {
		x, y = y, x%y
	}
	return x
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
// slow
func fct(pq int64) ([]byte, []byte) {
	x := int64(2)
	y := int64(2)
	d := int64(1)
	fmt.Println("[*] splitting ...")
	for d == 1 {
		x = g(x, pq)
		y = g(g(y, pq), pq)

		d = gcd(abs(x-y), pq)
		/*if d == pq || pq/d == 1 {
			fmt.Println("repeating")
			x = 2
			y = 2
			d = 1
		}*/
	}

	p := make([]byte, 4)
	q := make([]byte, 4)

	binary.BigEndian.PutUint32(p, uint32(pq/d))
	binary.BigEndian.PutUint32(q, uint32(d))

	return p, q
}
