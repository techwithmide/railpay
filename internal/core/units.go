package core

import "math/big"

const NativePerMicro = 1_000_000_000_000

var nativePerMicro = big.NewInt(NativePerMicro)

func NativeToMicro(v *big.Int) (micro uint64, ok bool) {
	if v == nil || v.Sign() < 0 {
		return 0, false
	}
	q := new(big.Int).Quo(v, nativePerMicro)
	if !q.IsUint64() {
		return 0, false
	}
	return q.Uint64(), true
}

func CeilNativeToMicro(v *big.Int) (micro uint64, ok bool) {
	if v == nil || v.Sign() < 0 {
		return 0, false
	}
	q, r := new(big.Int).QuoRem(v, nativePerMicro, new(big.Int))
	if r.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsUint64() {
		return 0, false
	}
	return q.Uint64(), true
}

func MicroToNative(m uint64) *big.Int {
	return new(big.Int).Mul(new(big.Int).SetUint64(m), nativePerMicro)
}
