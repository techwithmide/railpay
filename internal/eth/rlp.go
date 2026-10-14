package eth

import (
	"errors"
	"math/big"
)

func EncodeBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return []byte{b[0]}
	}
	return append(lengthPrefix(len(b), 0x80), b...)
}

func EncodeUint(v *big.Int) []byte {
	if v == nil || v.Sign() == 0 {
		return []byte{0x80}
	}
	return EncodeBytes(v.Bytes())
}

func EncodeList(items ...[]byte) []byte {
	var payload []byte
	for _, it := range items {
		payload = append(payload, it...)
	}
	return append(lengthPrefix(len(payload), 0xc0), payload...)
}

func lengthPrefix(n int, base byte) []byte {
	if n < 56 {
		return []byte{base + byte(n)}
	}
	var lb []byte
	for x := n; x > 0; x >>= 8 {
		lb = append([]byte{byte(x)}, lb...)
	}
	return append([]byte{base + 55 + byte(len(lb))}, lb...)
}

type rlpItem struct {
	list bool
	data []byte
}

var errRLP = errors.New("eth: malformed or non-canonical RLP")

func decodeItem(b []byte) (rlpItem, []byte, error) {
	if len(b) == 0 {
		return rlpItem{}, nil, errRLP
	}
	p := b[0]
	switch {
	case p < 0x80:
		return rlpItem{data: b[:1]}, b[1:], nil
	case p < 0xb8:
		n := int(p - 0x80)
		if len(b) < 1+n || (n == 1 && b[1] < 0x80) {
			return rlpItem{}, nil, errRLP
		}
		return rlpItem{data: b[1 : 1+n]}, b[1+n:], nil
	case p < 0xc0:
		n, hdr, err := longLen(b, 0xb7)
		if err != nil || len(b) < hdr+n {
			return rlpItem{}, nil, errRLP
		}
		return rlpItem{data: b[hdr : hdr+n]}, b[hdr+n:], nil
	case p < 0xf8:
		n := int(p - 0xc0)
		if len(b) < 1+n {
			return rlpItem{}, nil, errRLP
		}
		return rlpItem{list: true, data: b[1 : 1+n]}, b[1+n:], nil
	default:
		n, hdr, err := longLen(b, 0xf7)
		if err != nil || len(b) < hdr+n {
			return rlpItem{}, nil, errRLP
		}
		return rlpItem{list: true, data: b[hdr : hdr+n]}, b[hdr+n:], nil
	}
}

func longLen(b []byte, base byte) (n, hdr int, err error) {
	ll := int(b[0] - base)
	if ll < 1 || ll > 4 || len(b) < 1+ll || b[1] == 0 {
		return 0, 0, errRLP
	}
	for i := 0; i < ll; i++ {
		n = n<<8 | int(b[1+i])
	}
	if n < 56 {
		return 0, 0, errRLP
	}
	return n, 1 + ll, nil
}

func decodeList(payload []byte) ([]rlpItem, error) {
	var out []rlpItem
	for len(payload) > 0 {
		it, rest, err := decodeItem(payload)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
		payload = rest
	}
	return out, nil
}

func uintFrom(it rlpItem) (*big.Int, error) {
	if it.list || (len(it.data) > 0 && it.data[0] == 0) {
		return nil, errRLP
	}
	return new(big.Int).SetBytes(it.data), nil
}
