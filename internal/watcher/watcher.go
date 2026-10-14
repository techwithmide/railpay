package watcher

import (
	"arcpay/internal/chain"
	"arcpay/internal/core"
	"arcpay/internal/store"
	"context"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"time"
)

type ChainClient interface {
	BlockNumber(ctx context.Context) (uint64, error)
	TransferLogs(ctx context.Context, token string, from, to uint64, recipients []string) ([]chain.Log, error)
}

type Config struct {
	Token        string
	PollInterval time.Duration
	MaxRange     uint64
	LateWindow   time.Duration
	StartBlock   uint64
}

type Watcher struct {
	cfg   Config
	rpc   ChainClient
	store store.Store
	log   *slog.Logger
	now   func() time.Time
}

func New(cfg Config, rpc ChainClient, st store.Store, log *slog.Logger) *Watcher {
	if cfg.Token == "" {
		cfg.Token = chain.SystemEmitter
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 2 * time.Second
	}
	if cfg.MaxRange == 0 {
		cfg.MaxRange = 1000
	}
	if cfg.LateWindow == 0 {
		cfg.LateWindow = 7 * 24 * time.Hour
	}
	if log == nil {
		log = slog.Default()
	}
	return &Watcher{cfg: cfg, rpc: rpc, store: st, log: log, now: time.Now}
}

func (w *Watcher) Run(ctx context.Context) {
	backoff := w.cfg.PollInterval
	for ctx.Err() == nil {
		if _, err := w.store.ExpireDue(ctx, w.now()); err != nil {
			w.log.Error("expire sweep failed", "err", err)
		}
		caughtUp, err := w.Tick(ctx)
		wait := w.cfg.PollInterval
		if err != nil {
			w.log.Error("watcher tick failed", "err", err)
			backoff = min(backoff*2, 15*time.Second)
			wait = backoff
		} else {
			backoff = w.cfg.PollInterval
			if !caughtUp {
				wait = 250 * time.Millisecond
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
}

func (w *Watcher) Tick(ctx context.Context) (caughtUp bool, err error) {
	head, err := w.rpc.BlockNumber(ctx)
	if err != nil {
		return false, err
	}
	cur, ok, err := w.store.Cursor(ctx)
	if err != nil {
		return false, err
	}
	if !ok {
		cur = head
		if w.cfg.StartBlock > 0 && w.cfg.StartBlock <= head {
			cur = w.cfg.StartBlock - 1
		}
		if err := w.store.SetCursor(ctx, cur); err != nil {
			return false, err
		}
	}
	if cur >= head {
		return true, nil
	}
	from, to := cur+1, min(head, cur+w.cfg.MaxRange)

	now := w.now()
	addrs, err := w.store.WatchedAddresses(ctx, now, w.cfg.LateWindow)
	if err != nil {
		return false, err
	}
	if len(addrs) > 0 {
		logs, err := w.rpc.TransferLogs(ctx, w.cfg.Token, from, to, addrs)
		if err != nil {
			return false, err
		}
		for _, l := range logs {
			if err := w.handle(ctx, l, now); err != nil {
				return false, err
			}
		}
	}
	if err := w.store.SetCursor(ctx, to); err != nil {
		return false, err
	}
	return to >= head, nil
}

func (w *Watcher) handle(ctx context.Context, l chain.Log, now time.Time) error {
	t, err := chain.ParseTransfer(l)
	if err != nil {
		w.log.Warn("skipping unparsable log", "tx", l.TransactionHash, "err", err)
		return nil
	}
	amt := t.Amount
	if strings.EqualFold(w.cfg.Token, "0xfffffffffffffffffffffffffffffffffffffffe") {
		amt = new(big.Int).Div(amt, big.NewInt(1_000_000_000_000))
	}
	if amt.Sign() == 0 || !amt.IsUint64() {
		return nil
	}
	applied, err := w.store.RecordPayment(ctx, t.To, core.Payment{
		TxHash: t.TxHash, LogIndex: t.LogIndex, BlockNumber: t.Block, From: t.From, Amount: amt.Uint64(),
	}, now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return err
	case applied:
		w.log.Info("payment recorded", "to", t.To, "tx", t.TxHash, "amount", core.FormatUSDC(t.Amount.Uint64()))
	}
	return nil
}
