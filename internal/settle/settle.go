package settle

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"arcpay/internal/chain"
	"arcpay/internal/core"
	"arcpay/internal/eth"
	"arcpay/internal/signer"
	"arcpay/internal/store"
	"arcpay/internal/sweep/plan"
)

type Chain interface {
	BalanceAt(ctx context.Context, addr string) (*big.Int, error)
	PendingNonceAt(ctx context.Context, addr string) (uint64, error)
	BaseFee(ctx context.Context) (*big.Int, error)
	TipCap(ctx context.Context) (*big.Int, error)
	CodeAt(ctx context.Context, addr string) ([]byte, error)
	SendRawTransaction(ctx context.Context, raw []byte) error
	Receipt(ctx context.Context, txHash string) (*chain.Receipt, error)
}

type Signer interface {
	Sign(ctx context.Context, req signer.SignRequest) (*signer.SignResult, error)
	Destination(ctx context.Context, merchantID string) (signer.Destination, error)
}

type Config struct {
	ChainID          uint64
	MinPayoutMicro   uint64
	Batch            int
	Poll             time.Duration
	Lease            time.Duration
	RebroadcastAfter time.Duration
	FailAfter        time.Duration
	MaxAttempts      int
	Now              func() time.Time
}

type Worker struct {
	cfg Config
	ch  Chain
	sg  Signer
	st  store.Store
	log *slog.Logger
}

func New(cfg Config, ch Chain, sg Signer, st store.Store, log *slog.Logger) *Worker {
	if cfg.MinPayoutMicro == 0 {
		cfg.MinPayoutMicro = 10_000
	}
	if cfg.Batch == 0 {
		cfg.Batch = 20
	}
	if cfg.Poll == 0 {
		cfg.Poll = time.Second
	}
	if cfg.Lease == 0 {
		cfg.Lease = 2 * time.Minute
	}
	if cfg.RebroadcastAfter == 0 {
		cfg.RebroadcastAfter = 15 * time.Second
	}
	if cfg.FailAfter == 0 {
		cfg.FailAfter = 30 * time.Minute
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 12
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Worker{cfg: cfg, ch: ch, sg: sg, st: st, log: log}
}

func (w *Worker) Run(ctx context.Context) {
	for ctx.Err() == nil {
		n, err := w.Tick(ctx)
		if err != nil {
			w.log.Error("settle tick failed", "err", err)
		}
		if err != nil || n == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(w.cfg.Poll):
			}
		}
	}
}

func (w *Worker) Tick(ctx context.Context) (int, error) {
	if halted, why := w.st.Ledger().Halted(); halted {
		w.log.Warn("ledger halted: not sweeping", "reason", why)
		return 0, nil
	}
	jobs, err := w.st.LeaseSweepJobs(ctx, w.cfg.Now(), w.cfg.Batch, w.cfg.Lease)
	if err != nil {
		return 0, err
	}
	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		if err := w.Process(ctx, j); err != nil {
			w.log.Error("sweep job error", "job", j.ID, "err", err)
		}
	}
	return len(jobs), nil
}

func backoff(attempts int) time.Duration {
	d := 5 * time.Second << min(attempts, 8)
	return min(d, time.Hour)
}

func (w *Worker) wait(ctx context.Context, j core.SweepJob, reason string, d time.Duration, attempt bool) error {
	now := w.cfg.Now()
	j.Reason, j.NextRun, j.LeaseUntil = reason, now.Add(d), time.Time{}
	if attempt {
		j.Attempts++
		j.LastError = reason
	}
	_, err := w.st.SaveSweepJob(ctx, j, now)
	return err
}

func (w *Worker) fail(ctx context.Context, j core.SweepJob, reason string) error {
	now := w.cfg.Now()
	w.log.Error("sweep job failed", "job", j.ID, "intent", j.IntentID, "reason", reason)
	j.State, j.Reason, j.LastError, j.LeaseUntil = core.SweepFailed, reason, reason, time.Time{}
	_, err := w.st.SaveSweepJob(ctx, j, now)
	return err
}

func (w *Worker) transient(ctx context.Context, j core.SweepJob, what string, err error) error {
	reason := what + ": " + err.Error()
	if j.Attempts+1 >= w.cfg.MaxAttempts {
		return w.fail(ctx, j, "giving up after repeated errors: "+reason)
	}
	return w.wait(ctx, j, reason, backoff(j.Attempts), true)
}

func (w *Worker) Process(ctx context.Context, j core.SweepJob) error {
	var err error
	if j.State == core.SweepQueued {
		var done bool
		if j, done, err = w.plan(ctx, j); err != nil || done {
			return err
		}
	}
	if j.State == core.SweepSigned {
		var done bool
		if j, done, err = w.submit(ctx, j); err != nil || done {
			return err
		}
	}
	if j.State == core.SweepSubmitted {
		return w.verify(ctx, j)
	}
	return nil
}

func (w *Worker) plan(ctx context.Context, j core.SweepJob) (core.SweepJob, bool, error) {
	now := w.cfg.Now()
	d, err := w.sg.Destination(ctx, j.MerchantID)
	if err != nil {
		return j, true, w.transient(ctx, j, "reading settlement destination", err)
	}
	if d.Active == "" {
		reason := "merchant has no active settlement address"
		if d.Pending != "" {
			reason += " (a new address is waiting to be activated)"
		}
		return j, true, w.wait(ctx, j, reason, 5*time.Minute, false)
	}
	dest, err := eth.ParseAddress(d.Active)
	if err != nil {
		return j, true, w.fail(ctx, j, "signer reported an invalid active destination")
	}
	owed, err := w.st.OwedMicro(ctx, j.MerchantID, j.IntentID)
	if err != nil {
		return j, true, w.transient(ctx, j, "reading ledger", err)
	}
	if owed == 0 {
		return j, true, w.wait(ctx, j, "nothing owed", 10*time.Minute, false)
	}

	bal, err := w.ch.BalanceAt(ctx, j.DepositAddress)
	if err != nil {
		return j, true, w.transient(ctx, j, "reading balance", err)
	}
	if bal.Cmp(core.MicroToNative(owed)) < 0 {
		return j, true, w.transient(ctx, j, "chain balance is below what the ledger owes (stale node?)",
			fmt.Errorf("balance %s, owed %s", plan.FormatNative(bal), core.FormatUSDC(owed)))
	}
	code, err := w.ch.CodeAt(ctx, dest.Lower())
	if err != nil {
		return j, true, w.transient(ctx, j, "checking destination", err)
	}
	if len(code) > 0 {
		return j, true, w.wait(ctx, j, "settlement address is a contract; a plain transfer needs an ordinary wallet address", 10*time.Minute, false)
	}
	base, err := w.ch.BaseFee(ctx)
	if err != nil {
		return j, true, w.transient(ctx, j, "reading base fee", err)
	}
	tip, err := w.ch.TipCap(ctx)
	if err != nil {
		return j, true, w.transient(ctx, j, "reading tip", err)
	}
	p, err := plan.Compute(plan.Input{Balance: core.MicroToNative(owed), GasLimit: plan.TransferGas, BaseFee: base, Tip: tip})
	if err != nil {
		return j, true, w.wait(ctx, j, "payout does not cover the network fee yet: "+err.Error(), 10*time.Minute, false)
	}
	charge, ok := core.CeilNativeToMicro(p.MaxFee)
	if !ok || charge >= owed {
		return j, true, w.wait(ctx, j, "payout does not cover the network fee yet", 10*time.Minute, false)
	}
	value := owed - charge
	if value < w.cfg.MinPayoutMicro {
		return j, true, w.wait(ctx, j, fmt.Sprintf("below the minimum payout (%s)", core.FormatUSDC(w.cfg.MinPayoutMicro)), 10*time.Minute, false)
	}
	nonce, err := w.ch.PendingNonceAt(ctx, j.DepositAddress)
	if err != nil {
		return j, true, w.transient(ctx, j, "reading nonce", err)
	}
	valueNative := core.MicroToNative(value)

	res, err := w.sg.Sign(ctx, signer.SignRequest{
		MerchantID: j.MerchantID, IntentID: j.IntentID, JobID: j.ID, ChainID: w.cfg.ChainID, Nonce: nonce,
		GasTipCap: p.Tip.String(), GasFeeCap: p.FeeCap.String(), Gas: plan.TransferGas,
		To: dest.Lower(), Value: valueNative.String(),
	})
	var pe *signer.PolicyError
	switch {
	case errors.As(err, &pe):
		return j, true, w.wait(ctx, j, "signer declined: "+pe.Reason, 5*time.Minute, false)
	case err != nil:
		return j, true, w.transient(ctx, j, "signing", err)
	}

	raw, err := hex.DecodeString(strings.TrimPrefix(res.Raw, "0x"))
	if err != nil {
		return j, true, w.fail(ctx, j, "signer returned malformed transaction")
	}
	dec, err := eth.DecodeDynamicFeeTx(raw)
	if err != nil {
		return j, true, w.fail(ctx, j, "signer returned an undecodable transaction: "+err.Error())
	}
	if dec.From.Lower() != strings.ToLower(j.DepositAddress) || dec.Tx.To != dest || dec.Tx.Value.Cmp(valueNative) != 0 ||
		dec.Tx.Nonce != nonce || dec.Tx.ChainID.Uint64() != w.cfg.ChainID || len(dec.Tx.Data) != 0 ||
		dec.Tx.Gas != plan.TransferGas || dec.Tx.GasFeeCap.Cmp(p.FeeCap) > 0 {
		return j, true, w.fail(ctx, j, "signed transaction does not match the plan")
	}

	t := now.UTC()
	j.Destination, j.ChainID, j.Nonce = dest.Lower(), w.cfg.ChainID, nonce
	j.OwedMicro, j.ValueMicro, j.ChargeMicro = owed, value, charge
	j.ValueNative, j.MaxFeeNative = valueNative.String(), p.MaxFee.String()
	j.RawTx, j.TxHash = "0x"+hex.EncodeToString(raw), "0x"+hex.EncodeToString(dec.Hash[:])
	j.State, j.SignedAt, j.Reason, j.LeaseUntil = core.SweepSigned, &t, "", time.Time{}
	saved, err := w.st.SaveSweepJob(ctx, j, now)
	if err != nil {
		return j, true, err
	}
	return saved, false, nil
}

func (w *Worker) submit(ctx context.Context, j core.SweepJob) (core.SweepJob, bool, error) {
	now := w.cfg.Now()
	raw, err := hex.DecodeString(strings.TrimPrefix(j.RawTx, "0x"))
	if err != nil {
		return j, true, w.fail(ctx, j, "stored transaction is corrupt")
	}
	if err := w.ch.SendRawTransaction(ctx, raw); err != nil && !isKnown(err) {
		if r, rerr := w.ch.Receipt(ctx, j.TxHash); rerr == nil && r != nil {
		} else if isNonceTooLow(err) {
			return j, true, w.fail(ctx, j, "the deposit address nonce was already used by another transaction (manual sweep?); reconcile manually")
		} else if isInsufficient(err) {
			return j, true, w.fail(ctx, j, "deposit address cannot pay for the transfer: "+err.Error())
		} else {
			return j, true, w.transient(ctx, j, "broadcasting", err)
		}
	}
	t := now.UTC()
	j.State, j.SubmittedAt, j.Reason, j.LeaseUntil, j.NextRun = core.SweepSubmitted, &t, "", time.Time{}, now.Add(time.Second)
	saved, err := w.st.SaveSweepJob(ctx, j, now)
	if err != nil {
		return j, true, err
	}
	return saved, false, nil
}

func (w *Worker) verify(ctx context.Context, j core.SweepJob) error {
	now := w.cfg.Now()
	r, err := w.ch.Receipt(ctx, j.TxHash)
	if err != nil {
		return w.transient(ctx, j, "reading receipt", err)
	}
	if r == nil {
		since := now.Sub(*j.SubmittedAt)
		if since > w.cfg.FailAfter {
			return w.fail(ctx, j, "transaction not mined after "+w.cfg.FailAfter.String()+"; check the network and requeue")
		}
		if since > w.cfg.RebroadcastAfter {
			if raw, e := hex.DecodeString(strings.TrimPrefix(j.RawTx, "0x")); e == nil {
				if e := w.ch.SendRawTransaction(ctx, raw); e != nil && !isKnown(e) {
					w.log.Warn("rebroadcast failed", "job", j.ID, "err", e)
				}
			}
		}
		return w.wait(ctx, j, "waiting for the transaction to be mined", time.Second, false)
	}
	if !strings.EqualFold(r.TxHash, j.TxHash) {
		return w.fail(ctx, j, "receipt does not match the signed transaction")
	}
	if r.Status != 1 {
		return w.fail(ctx, j, "transaction reverted on-chain; the network fee was spent and funds did not move")
	}
	price := r.EffectiveGasPrice
	if price == nil {
		price = new(big.Int).Div(mustBig(j.MaxFeeNative), big.NewInt(plan.TransferGas))
	}
	fee := new(big.Int).Mul(new(big.Int).SetUint64(r.GasUsed), price)
	done, err := w.st.CompleteSweep(ctx, j.ID, store.SweepResult{TxHash: r.TxHash, BlockNumber: r.BlockNumber, GasUsed: r.GasUsed, FeeNative: fee}, now)
	if err != nil {
		if errors.Is(err, store.ErrInvalid) {
			return w.fail(ctx, j, "could not reconcile receipt: "+err.Error())
		}
		return w.transient(ctx, j, "completing sweep", err)
	}
	w.log.Info("payout confirmed", "job", done.ID, "intent", done.IntentID, "tx", done.TxHash, "amount", core.FormatUSDC(done.ValueMicro))
	return nil
}

func mustBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return new(big.Int)
	}
	return v
}

func lower(err error) string { return strings.ToLower(err.Error()) }

func isKnown(err error) bool {
	s := lower(err)
	return strings.Contains(s, "already known") || strings.Contains(s, "known transaction") || strings.Contains(s, "already in mempool")
}
func isNonceTooLow(err error) bool { return strings.Contains(lower(err), "nonce too low") }
func isInsufficient(err error) bool {
	s := lower(err)
	return strings.Contains(s, "insufficient funds") || strings.Contains(s, "insufficient balance")
}
