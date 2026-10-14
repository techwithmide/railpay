package eth

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

type Address [20]byte

func addressFromPub(x, y *big.Int) Address {
	pub := append(pad32(x), pad32(y)...)
	h := Keccak256(pub)
	var a Address
	copy(a[:], h[12:])
	return a
}

func AddressFromPrivateKey(priv []byte) (Address, error) {
	x, y, err := PublicKey(priv)
	if err != nil {
		return Address{}, err
	}
	return addressFromPub(x, y), nil
}

func (a Address) IsZero() bool { return a == Address{} }

func (a Address) Lower() string { return "0x" + hex.EncodeToString(a[:]) }

func (a Address) Hex() string {
	lower := hex.EncodeToString(a[:])
	h := Keccak256([]byte(lower))
	out := []byte(lower)
	for i, c := range out {
		if c >= 'a' && c <= 'f' {
			nib := h[i/2]
			if i%2 == 0 {
				nib >>= 4
			} else {
				nib &= 0x0f
			}
			if nib >= 8 {
				out[i] = c - 32
			}
		}
	}
	return "0x" + string(out)
}

func (a Address) String() string { return a.Hex() }

func ParseAddress(s string) (Address, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "0x") || len(s) != 42 {
		return Address{}, fmt.Errorf("%q is not a 0x-prefixed 40-hex-digit address", s)
	}
	raw, err := hex.DecodeString(s[2:])
	if err != nil {
		return Address{}, fmt.Errorf("%q is not a 0x-prefixed 40-hex-digit address", s)
	}
	var a Address
	copy(a[:], raw)
	body := s[2:]
	if body != strings.ToLower(body) && body != strings.ToUpper(body) && a.Hex() != s {
		return Address{}, fmt.Errorf("%q has an invalid checksum (typo?); expected %s", s, a.Hex())
	}
	return a, nil
}
