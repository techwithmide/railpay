package eth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"math/big"
)

type Signature struct {
	R, S *big.Int
	V    byte
}

func nonceGen(priv, hash []byte) func() *big.Int {
	z := new(big.Int).SetBytes(hash)
	z.Mod(z, secpN)
	h1 := pad32(z)
	v := bytes.Repeat([]byte{0x01}, 32)
	k := make([]byte, 32)
	mac := func(key []byte, parts ...[]byte) []byte {
		m := hmac.New(sha256.New, key)
		for _, p := range parts {
			m.Write(p)
		}
		return m.Sum(nil)
	}
	k = mac(k, v, []byte{0x00}, priv, h1)
	v = mac(k, v)
	k = mac(k, v, []byte{0x01}, priv, h1)
	v = mac(k, v)
	return func() *big.Int {
		for {
			v = mac(k, v)
			c := new(big.Int).SetBytes(v)
			k = mac(k, v, []byte{0x00})
			v = mac(k, v)
			if c.Sign() > 0 && c.Cmp(secpN) < 0 {
				return c
			}
		}
	}
}

func Sign(priv, hash []byte) (Signature, error) {
	if !validPrivKey(priv) {
		return Signature{}, errors.New("eth: invalid private key")
	}
	if len(hash) != 32 {
		return Signature{}, errors.New("eth: hash must be 32 bytes")
	}
	d := new(big.Int).SetBytes(priv)
	z := new(big.Int).SetBytes(hash)
	next := nonceGen(priv, hash)
	for {
		k := next()
		rx, ry, ok := scalarMult(k, secpGx, secpGy).affine()
		if !ok {
			continue
		}
		if rx.Cmp(secpN) >= 0 {
			continue
		}
		r := new(big.Int).Set(rx)
		if r.Sign() == 0 {
			continue
		}
		s := new(big.Int).Mul(r, d)
		s.Add(s, z)
		s.Mul(s, new(big.Int).ModInverse(k, secpN))
		s.Mod(s, secpN)
		if s.Sign() == 0 {
			continue
		}
		v := byte(ry.Bit(0))
		if s.Cmp(secpHalfN) > 0 {
			s.Sub(secpN, s)
			v ^= 1
		}
		return Signature{R: r, S: s, V: v}, nil
	}
}

func Recover(hash []byte, sig Signature) (Address, error) {
	if len(hash) != 32 {
		return Address{}, errors.New("eth: hash must be 32 bytes")
	}
	if sig.R == nil || sig.S == nil || sig.V > 1 {
		return Address{}, errors.New("eth: malformed signature")
	}
	if sig.R.Sign() <= 0 || sig.R.Cmp(secpN) >= 0 || sig.S.Sign() <= 0 || sig.S.Cmp(secpN) >= 0 {
		return Address{}, errors.New("eth: signature out of range")
	}
	rhs := new(big.Int).Mul(sig.R, sig.R)
	rhs.Mul(rhs, sig.R)
	rhs.Add(rhs, bigSeven)
	y := sqrtP(rhs)
	if y == nil {
		return Address{}, errors.New("eth: r is not a valid curve x-coordinate")
	}
	if byte(y.Bit(0)) != sig.V {
		y.Sub(secpP, y)
	}
	z := new(big.Int).SetBytes(hash)
	rinv := new(big.Int).ModInverse(sig.R, secpN)
	u1 := new(big.Int).Neg(z)
	u1.Mul(u1, rinv)
	u1.Mod(u1, secpN)
	u2 := new(big.Int).Mul(sig.S, rinv)
	u2.Mod(u2, secpN)
	q := jacAdd(scalarMult(u1, secpGx, secpGy), scalarMult(u2, sig.R, y))
	qx, qy, ok := q.affine()
	if !ok {
		return Address{}, errors.New("eth: recovered point at infinity")
	}
	return addressFromPub(qx, qy), nil
}
