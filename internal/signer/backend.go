package signer

import (
	"arcpay/internal/eth"
	"arcpay/internal/wallet"
	"errors"
)

type LocalBackend struct{ secret string }

func NewLocalBackend(secret string) (*LocalBackend, error) {
	if len(secret) < 32 {
		return nil, errors.New("signer: derivation secret must be at least 32 characters")
	}
	return &LocalBackend{secret: secret}, nil
}

func (b *LocalBackend) Address(merchantID, intentID string) (eth.Address, error) {
	k, err := wallet.DeriveKey(b.secret, merchantID, intentID)
	if err != nil {
		return eth.Address{}, err
	}
	defer wipe(k)
	return eth.AddressFromPrivateKey(k)
}

func (b *LocalBackend) Sign(merchantID, intentID string, tx *eth.DynamicFeeTx) (*eth.SignedTx, error) {
	k, err := wallet.DeriveKey(b.secret, merchantID, intentID)
	if err != nil {
		return nil, err
	}
	defer wipe(k)
	return tx.Sign(k)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
