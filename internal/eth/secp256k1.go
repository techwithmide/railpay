package eth

import (
	"errors"
	"math/big"
)

var (
	secpP     = mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	secpN     = mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	secpGx    = mustHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	secpGy    = mustHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	secpHalfN = new(big.Int).Rsh(secpN, 1)
	bigThree  = big.NewInt(3)
	bigSeven  = big.NewInt(7)
)

func mustHex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex constant")
	}
	return v
}

type jacobian struct{ x, y, z *big.Int }

func infinity() jacobian { return jacobian{new(big.Int), new(big.Int), new(big.Int)} }

func (p jacobian) isInf() bool { return p.z.Sign() == 0 }

func modp(v *big.Int) *big.Int { return v.Mod(v, secpP) }

func mulp(a, b *big.Int) *big.Int { return modp(new(big.Int).Mul(a, b)) }

func jacDouble(p jacobian) jacobian {
	if p.isInf() || p.y.Sign() == 0 {
		return infinity()
	}
	ysq := mulp(p.y, p.y)
	s := mulp(p.x, ysq)
	s.Lsh(s, 2)
	modp(s)
	m := mulp(p.x, p.x)
	m.Mul(m, bigThree)
	modp(m)
	x3 := mulp(m, m)
	x3.Sub(x3, new(big.Int).Lsh(s, 1))
	modp(x3)
	y3 := new(big.Int).Sub(s, x3)
	y3.Mul(y3, m)
	y4 := mulp(ysq, ysq)
	y4.Lsh(y4, 3)
	y3.Sub(y3, y4)
	modp(y3)
	z3 := mulp(p.y, p.z)
	z3.Lsh(z3, 1)
	modp(z3)
	return jacobian{x3, y3, z3}
}

func jacAdd(p, q jacobian) jacobian {
	if p.isInf() {
		return q
	}
	if q.isInf() {
		return p
	}
	z1sq, z2sq := mulp(p.z, p.z), mulp(q.z, q.z)
	u1, u2 := mulp(p.x, z2sq), mulp(q.x, z1sq)
	s1, s2 := mulp(p.y, mulp(z2sq, q.z)), mulp(q.y, mulp(z1sq, p.z))
	h := modp(new(big.Int).Sub(u2, u1))
	r := modp(new(big.Int).Sub(s2, s1))
	if h.Sign() == 0 {
		if r.Sign() == 0 {
			return jacDouble(p)
		}
		return infinity()
	}
	h2 := mulp(h, h)
	h3 := mulp(h2, h)
	v := mulp(u1, h2)
	x3 := mulp(r, r)
	x3.Sub(x3, h3)
	x3.Sub(x3, new(big.Int).Lsh(v, 1))
	modp(x3)
	y3 := new(big.Int).Sub(v, x3)
	y3.Mul(y3, r)
	y3.Sub(y3, mulp(s1, h3))
	modp(y3)
	z3 := mulp(mulp(h, p.z), q.z)
	return jacobian{x3, y3, z3}
}

func scalarMult(k, px, py *big.Int) jacobian {
	base := jacobian{new(big.Int).Set(px), new(big.Int).Set(py), big.NewInt(1)}
	acc := infinity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc = jacDouble(acc)
		if k.Bit(i) == 1 {
			acc = jacAdd(acc, base)
		}
	}
	return acc
}

func (p jacobian) affine() (x, y *big.Int, ok bool) {
	if p.isInf() {
		return nil, nil, false
	}
	zinv := new(big.Int).ModInverse(p.z, secpP)
	zinv2 := mulp(zinv, zinv)
	return mulp(p.x, zinv2), mulp(p.y, mulp(zinv2, zinv)), true
}

func validPrivKey(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	k := new(big.Int).SetBytes(b)
	return k.Sign() > 0 && k.Cmp(secpN) < 0
}

func PublicKey(priv []byte) (x, y *big.Int, err error) {
	if !validPrivKey(priv) {
		return nil, nil, errors.New("eth: invalid private key")
	}
	x, y, ok := scalarMult(new(big.Int).SetBytes(priv), secpGx, secpGy).affine()
	if !ok {
		return nil, nil, errors.New("eth: public key is the point at infinity")
	}
	return x, y, nil
}

func sqrtP(v *big.Int) *big.Int {
	e := new(big.Int).Add(secpP, big.NewInt(1))
	e.Rsh(e, 2)
	y := new(big.Int).Exp(v, e, secpP)
	if mulp(y, y).Cmp(new(big.Int).Mod(v, secpP)) != 0 {
		return nil
	}
	return y
}

func pad32(v *big.Int) []byte { return v.FillBytes(make([]byte, 32)) }
