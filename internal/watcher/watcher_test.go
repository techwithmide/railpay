package watcher

import (
	"context"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"arcpay/internal/chain"
	"arcpay/internal/core"
	"arcpay/internal/store"
)

const (
	token = chain.SystemEmitter
	dep   = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	payer = "0x1111111111111111111111111111111111111111"
)

type fakeChain struct {
	head uint64
	logs []chain.Log
}

func (f *fakeChain) BlockNumber(context.Context) (uint64, error) { return f.head, nil }
func (f *fakeChain) TransferLogs(_ context.Context, _ string, from, to uint64, recips []string) ([]chain.Log, error) {
	var out []chain.Log
	for _, l := range f.logs {
		blk, _ := chain.ParseQuantity(l.BlockNumber)
		if blk < from || blk > to {
			continue
		}
		for _, r := range recips {
			if l.Topics[2][26:] == r[2:] {
				out = append(out, l)
			}
		}
	}
	return out, nil
}

func pad(addr string) string { return "0x000000000000000000000000" + addr[2:] }

func transferLog(to string, amount int64, block, idx string, tx string) chain.Log {
	return chain.Log{
		Address: token, Topics: []string{chain.TransferTopic, pad(payer), pad(to)},
		Data:        "0x" + leftPad(new(big.Int).Mul(big.NewInt(amount), big.NewInt(1_000_000_000_000)).Text(16)),
		BlockNumber: block, TransactionHash: tx, LogIndex: idx,
	}
}

func leftPad(h string) string {
	for len(h) < 64 {
		h = "0" + h
	}
	return h
}

func TestWatcherRecordsOnceAndEmitsWebhook(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	st.SeedMerchant(core.Merchant{ID: "mch_1", Name: "M", Status: "active"}, "sk_test_k")
	now := time.Now()
	_, _, err := st.CreateIntent(ctx, &core.Intent{
		ID: "pi_1", MerchantID: "mch_1", Amount: 25_000_000, Status: core.StatusPending,
		DepositAddress: dep, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	fc := &fakeChain{head: 100, logs: []chain.Log{
		transferLog(dep, 25_000_000, "0x63", "0x0", "0xaa"),
		transferLog("0x2222222222222222222222222222222222222222", 5, "0x63", "0x1", "0xbb"),
		transferLog(dep, 0, "0x64", "0x0", "0xcc"),
	}}
	w := New(Config{}, fc, st, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := st.SetCursor(ctx, 98); err != nil {
		t.Fatal(err)
	}
	caughtUp, err := w.Tick(ctx)
	if err != nil || !caughtUp {
		t.Fatalf("tick: caughtUp=%v err=%v", caughtUp, err)
	}
	in, _ := st.GetIntent(ctx, "pi_1")
	if in.Status != core.StatusPaid || in.Received != 25_000_000 {
		t.Fatalf("intent not paid: %+v", in)
	}
	if cur, _, _ := st.Cursor(ctx); cur != 100 {
		t.Fatalf("cursor=%d", cur)
	}

	_ = st.SetCursor(ctx, 98)
	if _, err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	in, _ = st.GetIntent(ctx, "pi_1")
	if in.Received != 25_000_000 {
		t.Fatalf("double counted: %d", in.Received)
	}
	ds, _ := st.LeaseDeliveries(ctx, time.Now(), 10, time.Minute)
	if len(ds) != 1 || ds[0].Event.Type != core.EventSucceeded {
		t.Fatalf("want exactly one succeeded event, got %+v", ds)
	}
}

func TestWatcherFirstRunStartsAtHead(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	w := New(Config{}, &fakeChain{head: 500}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if caughtUp, err := w.Tick(ctx); err != nil || !caughtUp {
		t.Fatalf("caughtUp=%v err=%v", caughtUp, err)
	}
	if cur, ok, _ := st.Cursor(ctx); !ok || cur != 500 {
		t.Fatalf("cursor=%d ok=%v", cur, ok)
	}
}
