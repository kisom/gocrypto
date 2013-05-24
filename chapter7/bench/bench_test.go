package bench

import "testing"

func BenchmarkAESKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := generateAESKey()
		if err != nil {
			b.Fail()
		}
	}
}

func BenchmarkRSAKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := generateRSAKey()
		if err != nil {
			b.Fail()
		}
	}
}

func BenchmarkPrecomputedRSAKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		k, err := generateRSAKey()
		if err != nil {
			b.Fail()
		} else {
			k.Precompute()
		}
	}
}
