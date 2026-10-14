package reconcile

import (
	"arcpay/internal/core"
	"arcpay/internal/store"
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"time"
)

type Chain interface {
	BalanceAt(ctx context.Context, addr string) (*big.Int, error)
}

type Config struct {
	Interval           time.Duration
	Batch              int
	ShortfallTolerance uint64
	OnHalt             func(reason string)
	Now                func() time.Time
}

type Finding struct {
	Kind     string
	IntentID string
	Address  string
	Chain    string
	Ledger   string
	DiffNano *big.Int
}

type Result struct {
	LedgerOK bool
	Problems []string
	Checked  int
	Findings []Finding
	Halted   bool
}

type Worker struct {
	cfg    Config
	ch     Chain
	st     store.Store
	log    *slog.Logger
	cursor int
}

func New(cfg Config, ch Chain, st store.Store, log *slog.Logger) *Worker {
	if cfg.Interval == 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Batch == 0 {
		cfg.Batch = 50
	}
	if cfg.ShortfallTolerance == 0 {
		cfg.ShortfallTolerance = 10_000
	}
	if log == nil {
		log = slog.Default()
	}
	return &Worker{cfg: cfg, ch: ch, st: st, log: log}
}

func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	for {
		if res, err := w.Pass(ctx); err != nil {
			w.log.Error("reconcile pass failed", "err", err)
		} else if !res.LedgerOK || len(res.Findings) > 0 {
			w.log.Warn("reconcile findings", "ledger_ok", res.LedgerOK, "problems", res.Problems, "findings", len(res.Findings))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (w *Worker) halt(reason string) {
	book := w.st.Ledger()
	if already, _ := book.Halted(); already {
		return
	}
	book.Halt(reason)
	w.log.Error("LEDGER HALTED", "reason", reason)
	if w.cfg.OnHalt != nil {
		w.cfg.OnHalt(reason)
	}
}

func (w *Worker) Pass(ctx context.Context) (Result, error) {
	var res Result
	rep := w.st.Ledger().Verify()
	res.LedgerOK, res.Problems = rep.OK(), rep.Violations
	if !res.LedgerOK {
		w.halt(fmt.Sprintf("ledger verification failed: %v", rep.Violations))
		res.Halted = true
	}

	deps, err := w.st.Deposits(ctx)
	if err != nil {
		return res, err
	}
	if len(deps) == 0 {
		return res, nil
	}
	if w.cursor >= len(deps) {
		w.cursor = 0
	}
	n := min(w.cfg.Batch, len(deps))
	tol := core.MicroToNative(w.cfg.ShortfallTolerance)
	one := core.MicroToNative(1)
	for i := 0; i < n; i++ {
		d := deps[(w.cursor+i)%len(deps)]
		if d.Busy {
			continue
		}
		bal, err := w.ch.BalanceAt(ctx, d.Address)
		if err != nil {
			return res, err
		}
		res.Checked++
		want := core.MicroToNative(d.LedgerMicro)
		diff := new(big.Int).Sub(bal, want)
		f := Finding{IntentID: d.IntentID, Address: d.Address, Chain: bal.String(), Ledger: want.String(), DiffNano: diff}
		switch {
		case diff.Sign() < 0:
			f.Kind = "shortfall"
			res.Findings = append(res.Findings, f)
			if new(big.Int).Neg(diff).Cmp(tol) > 0 {
				w.halt(fmt.Sprintf("deposit %s holds %s native units, ledger expects %s", d.IntentID, bal, want))
				res.Halted = true
			}
		case diff.Cmp(one) >= 0:
			f.Kind = "surplus"
			res.Findings = append(res.Findings, f)
		}
	}
	w.cursor = (w.cursor + n) % len(deps)
	return res, nil
}
