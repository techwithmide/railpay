package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"arcpay/internal/chain"
	"arcpay/internal/eth"
	"arcpay/internal/sweep/plan"
	"arcpay/internal/wallet"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "\nerror:", err)
		if errors.Is(err, plan.ErrNothingToSweep) {
			fmt.Fprintln(os.Stderr, "hint: check --merchant and --intent are exact (the key is bound to both) and that DERIVE_SECRET and the RPC network match the gateway's")
		}
		os.Exit(1)
	}
}

func run() error {
	to := flag.String("to", "", "destination address (required)")
	merchant := flag.String("merchant", "", "merchant ID, e.g. mch_... (required: deposit keys are bound to the merchant)")
	intent := flag.String("intent", "", "payment intent ID, e.g. pi_... (required)")
	rpc := flag.String("rpc", os.Getenv("ARC_RPC_URL"), "Arc JSON-RPC URL (default $ARC_RPC_URL)")
	explorer := flag.String("explorer", os.Getenv("ARC_EXPLORER_URL"), "explorer base URL for the tx link (default: built in per chain ID, or $ARC_EXPLORER_URL)")
	dry := flag.Bool("dry-run", false, "show the plan without sending anything")
	yes := flag.Bool("yes", false, "skip the confirmation prompt")
	noWait := flag.Bool("no-wait", false, "return right after broadcasting instead of waiting for the receipt")
	flag.Parse()

	if *to == "" || *intent == "" || *merchant == "" {
		flag.Usage()
		return errors.New("--to, --merchant and --intent are required")
	}
	if *rpc == "" {
		return errors.New("set ARC_RPC_URL or pass --rpc")
	}
	secret := os.Getenv("DERIVE_SECRET")
	if secret == "" {
		return errors.New("DERIVE_SECRET is not set")
	}
	dest, err := eth.ParseAddress(*to)
	if err != nil {
		return fmt.Errorf("--to: %w", err)
	}
	if dest.IsZero() {
		return errors.New("--to is the zero address")
	}
	key, err := wallet.DeriveKey(secret, *merchant, *intent)
	if err != nil {
		return err
	}
	from, err := eth.AddressFromPrivateKey(key)
	if err != nil {
		return err
	}
	if from == dest {
		return errors.New("--to is the deposit address itself")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	c := &chain.Client{URL: *rpc, HTTP: &http.Client{Timeout: 15 * time.Second}}

	chainID, err := c.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("connecting to RPC: %w", err)
	}
	bal, err := c.BalanceAt(ctx, from.Lower())
	if err != nil {
		return err
	}
	nonce, err := c.PendingNonceAt(ctx, from.Lower())
	if err != nil {
		return err
	}
	base, err := c.BaseFee(ctx)
	if err != nil {
		return err
	}
	tip, err := c.TipCap(ctx)
	if err != nil {
		return err
	}
	gas, err := c.EstimateGas(ctx, from.Lower(), dest.Lower(), big.NewInt(1))
	if err != nil {
		return fmt.Errorf("estimating gas: %w", err)
	}
	if gas != plan.TransferGas {
		return fmt.Errorf("gas estimate is %d, not %d: the destination is not a plain wallet address", gas, plan.TransferGas)
	}
	p, err := plan.Compute(plan.Input{Balance: bal, GasLimit: gas, BaseFee: base, Tip: tip})

	fmt.Fprintln(os.Stderr, "WARNING: break-glass sweep. This bypasses the signer's policy and the ledger.")
	fmt.Printf("network:      %s (chain ID %d)\n", plan.NetworkName(chainID.Uint64()), chainID)
	fmt.Printf("deposit:      %s\n", from.Hex())
	fmt.Printf("balance:      %s USDC\n", plan.FormatNative(bal))
	if err != nil {
		return err
	}
	fmt.Printf("network fee:  up to %s USDC (gas %d)\n", plan.FormatNative(p.MaxFee), p.GasLimit)
	fmt.Printf("send:         %s USDC\n", plan.FormatNative(p.Value))
	fmt.Printf("to:           %s\n", dest.Hex())
	if *dry {
		fmt.Println("\ndry run: nothing sent")
		return nil
	}
	if !*yes {
		fmt.Print("\nSign and broadcast this transfer? Type 'yes' to continue: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return errors.New("aborted: no confirmation received")
		}
		if !strings.EqualFold(strings.TrimSpace(line), "yes") {
			return errors.New("aborted")
		}
	}

	signed, err := (&eth.DynamicFeeTx{
		ChainID: chainID, Nonce: nonce, GasTipCap: p.Tip, GasFeeCap: p.FeeCap,
		Gas: p.GasLimit, To: dest, Value: p.Value,
	}).Sign(key)
	if err != nil {
		return err
	}
	if err := c.SendRawTransaction(ctx, signed.Raw); err != nil {
		return fmt.Errorf("broadcast: %w", err)
	}
	hash := fmt.Sprintf("0x%x", signed.Hash)
	fmt.Printf("\nsubmitted:    %s\n", hash)
	if url := plan.TxURL(firstNonEmpty(*explorer, plan.DefaultExplorer(chainID.Uint64())), hash); url != "" {
		fmt.Printf("explorer:     %s\n", url)
	}
	if *noWait {
		return nil
	}
	for {
		r, err := c.Receipt(ctx, hash)
		if err != nil {
			return err
		}
		if r != nil {
			if r.Status != 1 {
				return fmt.Errorf("transaction %s reverted", hash)
			}
			fmt.Printf("confirmed:    block %d\n", r.BlockNumber)
			left, _ := c.BalanceAt(ctx, from.Lower())
			fmt.Printf("left behind:  %s USDC (refunded fee headroom)\n", plan.FormatNative(left))
			fmt.Fprintln(os.Stderr, "\nNOTE: the ledger was not updated. Expect a reconciliation shortfall for this deposit.")
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for %s; check the explorer", hash)
		case <-time.After(time.Second):
		}
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
