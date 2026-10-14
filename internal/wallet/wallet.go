package wallet

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"arcpay/internal/eth"
)

var curveOrder, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

func validScalar(b []byte) bool {
	k := new(big.Int).SetBytes(b)
	return k.Sign() > 0 && k.Cmp(curveOrder) < 0
}

func DeriveKey(secret, merchantID, intentID string) ([]byte, error) {
	if secret == "" {
		return nil, errors.New("wallet: empty secret")
	}
	if merchantID == "" || intentID == "" || len(merchantID) > 0xffff || len(intentID) > 0xffff {
		return nil, errors.New("wallet: merchant and intent IDs are required")
	}
	for ctr := uint32(0); ctr < 8; ctr++ {
		m := hmac.New(sha256.New, []byte(secret))
		m.Write([]byte("arcpay/v2"))
		var n [4]byte
		binary.BigEndian.PutUint16(n[:2], uint16(len(merchantID)))
		m.Write(n[:2])
		m.Write([]byte(merchantID))
		binary.BigEndian.PutUint16(n[:2], uint16(len(intentID)))
		m.Write(n[:2])
		m.Write([]byte(intentID))
		binary.BigEndian.PutUint32(n[:], ctr)
		m.Write(n[:])
		if k := m.Sum(nil); validScalar(k) {
			return k, nil
		}
	}
	return nil, errors.New("wallet: could not derive key")
}

func Address(secret, merchantID, intentID string) (string, error) {
	k, err := DeriveKey(secret, merchantID, intentID)
	if err != nil {
		return "", err
	}
	a, err := eth.AddressFromPrivateKey(k)
	if err != nil {
		return "", err
	}
	return a.Lower(), nil
}
