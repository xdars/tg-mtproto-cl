package main

import (
	"math/big"
)

var one = big.NewInt(1)
var two = big.NewInt(2)

func checkGCD(n, g *big.Int) (newN, newG *big.Int, ok bool) {
	var z big.Int
	g.Abs(g)
	z.GCD(nil, nil, n, g)

	if z.Cmp(n) == 0 {
		return nil, nil, false
	}

	if z.Cmp(one) == 0 {
		return nil, nil, false
	}

	n.Div(n, &z)

	return n, &z, true
}

func Brent(n *big.Int, start, c int64) (primes []*big.Int) {
	if n.ProbablyPrime(10) {
		return []*big.Int{n}
	}
	
	x1 := big.NewInt(start)
	x2 := big.NewInt(start*start + c)

	bigc := big.NewInt(c)

	for j := 0; j < 1000; j++ {
		x2.Exp(x2, two, n)
		x2.Add(x2, bigc)
	}

	limit := 1
	product := big.NewInt(1)

	terms := 0
	for terms < (1 << 16) {
		for j := 0; j < limit; j++ {
			x2.Exp(x2, two, n)
			x2.Add(x2, bigc)

			if x1.Cmp(x2) == 0 {
				break
			}

			var tmp big.Int
			tmp.Sub(x1, x2)
			product.Mul(product, &tmp)

			terms++
			if terms%16 == 0 {

				if newN, newG, ok := checkGCD(n, product); ok {
					pr := Brent(newN, start, c)
					primes = append(primes, pr...)
					pr = Brent(newG, start, c)
					primes = append(primes, pr...)
					return primes
				}

				product.SetInt64(1)
			}
		}

		x1.Set(x2)
		limit *= 2
		for j := 0; j < limit; j++ {
			x2.Exp(x2, two, n)
			x2.Add(x2, bigc)
		}
	}

	if n.Cmp(one) != 0 {
		if n.ProbablyPrime(10) {
			primes = append(primes, n)
		}
	}

	return primes
}
