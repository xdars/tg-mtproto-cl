package mtproto

import (
	"math/big"
	"testing"
	//"fmt"
)

func TestPQ(t *testing.T) {
	cases := []struct {
		pq, p, q *big.Int
	}{
		{big.NewInt(1724114033281923457), big.NewInt(1402015859), big.NewInt(1229739323)},
		{big.NewInt(378221), big.NewInt(613), big.NewInt(617)},
		//{big.NewInt(15), big.NewInt(3), big.NewInt(5)},
	}

	for i := 0; i < len(cases); i++ {
		primes := Brent(cases[i].pq, 10, 10)
		if cases[i].p.Cmp(primes[0]) != 0 || cases[i].q.Cmp(primes[1]) != 0 {
			t.Errorf("PQ mismatch: got %v %v, want %v %v", primes[0], primes[1], cases[i].p, cases[i].q)
		}
	}
}
