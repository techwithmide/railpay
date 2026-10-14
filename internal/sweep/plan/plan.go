package plan

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var (
	ErrNothingToSweep = errors.New("nothing to sweep: balance is zero")
	ErrInsufficient   = errors.New("balance does not cover the network fee")
)

const (
	NativeDecimals = 18
	TransferGas    = 21_000
)

type Input struct {
	Balance  *big.Int
	GasLimit uint64
	BaseFee  *big.Int
	Tip      *big.Int
}

type Plan struct {
	GasLimit uint64
	Tip      *big.Int
	FeeCap   *big.Int
	MaxFee   *big.Int
	Value    *big.Int
}

func Compute(in Input) (Plan, error) {
	if in.Balance == nil || in.Balance.Sign() <= 0 {
		return Plan{}, ErrNothingToSweep
	}
	if in.GasLimit == 0 {
		return Plan{}, errors.New("gas limit is zero")
	}
	if in.BaseFee == nil || in.BaseFee.Sign() < 0 || in.Tip == nil || in.Tip.Sign() < 0 {
		return Plan{}, errors.New("invalid fee inputs")
	}
	feeCap := new(big.Int).Mul(in.BaseFee, big.NewInt(125))
	feeCap.Div(feeCap, big.NewInt(100))
	feeCap.Add(feeCap, in.Tip)

	maxFee := new(big.Int).Mul(new(big.Int).SetUint64(in.GasLimit), feeCap)
	if in.Balance.Cmp(maxFee) <= 0 {
		return Plan{}, fmt.Errorf("%w: balance %s USDC, max fee %s USDC",
			ErrInsufficient, FormatNative(in.Balance), FormatNative(maxFee))
	}
	return Plan{
		GasLimit: in.GasLimit,
		Tip:      new(big.Int).Set(in.Tip),
		FeeCap:   feeCap,
		MaxFee:   maxFee,
		Value:    new(big.Int).Sub(in.Balance, maxFee),
	}, nil
}

func FormatNative(v *big.Int) string {
	if v == nil {
		return "0.00"
	}
	neg := v.Sign() < 0
	abs := new(big.Int).Abs(v)
	unit := new(big.Int).Exp(big.NewInt(10), big.NewInt(NativeDecimals), nil)
	whole, frac := new(big.Int).DivMod(abs, unit, new(big.Int))
	fs := fmt.Sprintf("%0*d", NativeDecimals, frac)
	fs = strings.TrimRight(fs, "0")
	for len(fs) < 2 {
		fs += "0"
	}
	s := whole.String() + "." + fs
	if neg {
		s = "-" + s
	}
	return s
}

func DefaultExplorer(chainID uint64) string {
	switch chainID {
	case 5042:
		return "https://explorer.arc.io"
	case 5042002:
		return "https://testnet.arcscan.app"
	}
	return ""
}

func NetworkName(chainID uint64) string {
	switch chainID {
	case 5042:
		return "Arc mainnet"
	case 5042002:
		return "Arc testnet"
	}
	return "unknown network"
}

func TxURL(base, hash string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return ""
	}
	return base + "/tx/" + hash
}
