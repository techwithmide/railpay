package eth

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
)

const dynamicFeeTxType = 0x02

type DynamicFeeTx struct {
	ChainID   *big.Int
	Nonce     uint64
	GasTipCap *big.Int
	GasFeeCap *big.Int
	Gas       uint64
	To        Address
	Value     *big.Int
	Data      []byte
}

type SignedTx struct {
	Tx   DynamicFeeTx
	Sig  Signature
	Raw  []byte
	Hash [32]byte
	From Address
}

func (t *DynamicFeeTx) fields() [][]byte {
	return [][]byte{
		EncodeUint(t.ChainID),
		EncodeUint(new(big.Int).SetUint64(t.Nonce)),
		EncodeUint(t.GasTipCap),
		EncodeUint(t.GasFeeCap),
		EncodeUint(new(big.Int).SetUint64(t.Gas)),
		EncodeBytes(t.To[:]),
		EncodeUint(t.Value),
		EncodeBytes(t.Data),
		EncodeList(),
	}
}

func (t *DynamicFeeTx) validate() error {
	if t.ChainID == nil || t.ChainID.Sign() <= 0 || t.GasTipCap == nil || t.GasFeeCap == nil || t.Value == nil {
		return errors.New("eth: transaction has unset fields")
	}
	if t.GasTipCap.Sign() < 0 || t.GasFeeCap.Sign() < 0 || t.Value.Sign() < 0 {
		return errors.New("eth: negative amount")
	}
	if t.GasTipCap.Cmp(t.GasFeeCap) > 0 {
		return errors.New("eth: tip cap exceeds fee cap")
	}
	return nil
}

func (t *DynamicFeeTx) SigningHash() [32]byte {
	return Keccak256([]byte{dynamicFeeTxType}, EncodeList(t.fields()...))
}

func (t *DynamicFeeTx) Sign(priv []byte) (*SignedTx, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	h := t.SigningHash()
	sig, err := Sign(priv, h[:])
	if err != nil {
		return nil, err
	}
	from, err := AddressFromPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	items := append(t.fields(),
		EncodeUint(new(big.Int).SetUint64(uint64(sig.V))),
		EncodeUint(sig.R),
		EncodeUint(sig.S),
	)
	raw := append([]byte{dynamicFeeTxType}, EncodeList(items...)...)
	return &SignedTx{Tx: *t, Sig: sig, Raw: raw, Hash: Keccak256(raw), From: from}, nil
}

func DecodeDynamicFeeTx(raw []byte) (*SignedTx, error) {
	if len(raw) < 2 || raw[0] != dynamicFeeTxType {
		return nil, errors.New("eth: not an EIP-1559 transaction")
	}
	top, rest, err := decodeItem(raw[1:])
	if err != nil || !top.list || len(rest) != 0 {
		return nil, errRLP
	}
	it, err := decodeList(top.data)
	if err != nil {
		return nil, err
	}
	if len(it) != 12 {
		return nil, fmt.Errorf("eth: expected 12 transaction fields, got %d", len(it))
	}
	var t DynamicFeeTx
	u := func(i int) (*big.Int, error) { return uintFrom(it[i]) }
	if t.ChainID, err = u(0); err != nil {
		return nil, err
	}
	nonce, err := u(1)
	if err != nil || !nonce.IsUint64() {
		return nil, errRLP
	}
	t.Nonce = nonce.Uint64()
	if t.GasTipCap, err = u(2); err != nil {
		return nil, err
	}
	if t.GasFeeCap, err = u(3); err != nil {
		return nil, err
	}
	gas, err := u(4)
	if err != nil || !gas.IsUint64() {
		return nil, errRLP
	}
	t.Gas = gas.Uint64()
	if it[5].list || len(it[5].data) != 20 {
		return nil, errors.New("eth: missing or malformed recipient (contract creation unsupported)")
	}
	copy(t.To[:], it[5].data)
	if t.Value, err = u(6); err != nil {
		return nil, err
	}
	if it[7].list {
		return nil, errRLP
	}
	t.Data = append([]byte(nil), it[7].data...)
	if !it[8].list || len(it[8].data) != 0 {
		return nil, errors.New("eth: access lists are not supported")
	}
	v, err := u(9)
	if err != nil || !v.IsUint64() || v.Uint64() > 1 {
		return nil, errors.New("eth: bad y-parity")
	}
	r, err := u(10)
	if err != nil {
		return nil, err
	}
	s, err := u(11)
	if err != nil {
		return nil, err
	}
	sig := Signature{R: r, S: s, V: byte(v.Uint64())}
	if sig.S.Cmp(secpHalfN) > 0 {
		return nil, errors.New("eth: high-s signature")
	}
	if err := t.validate(); err != nil {
		return nil, err
	}
	h := t.SigningHash()
	from, err := Recover(h[:], sig)
	if err != nil {
		return nil, err
	}
	re := append([]byte{dynamicFeeTxType}, EncodeList(append(t.fields(),
		EncodeUint(v), EncodeUint(r), EncodeUint(s))...)...)
	if !bytes.Equal(re, raw) {
		return nil, errRLP
	}
	return &SignedTx{Tx: t, Sig: sig, Raw: append([]byte(nil), raw...), Hash: Keccak256(raw), From: from}, nil
}
