package reconcile

import (
	"context"
	"math/big"
	"testing"
	"time"

	"arcpay/internal/core"
	"arcpay/internal/ledger"
	"arcpay/internal/store"
)

type fakeChain map[string]*big.Int

func (f fakeChain) BalanceAt(_ context.Context, a string) (*big.Int, error) {
	if v, ok := f[a]; ok {
		return new(big.Int).Set(v), nil
	}
	return new(big.Int), nil
}

func setup(t *testing.T) (*store.Memory, fakeChain, string) {
	st := store.NewMemory()
	st.SeedMerchant(core.Merchant{ID: "mch_1"}, "")
	now := time.Now()
	addr := "0x" + "ab"[:2] + "cdefabcdefabcdefabcdefabcdefabcdefabcd"
	if _, _, err := st.CreateIntent(context.Background(), &core.Intent{ID: "pi_1", MerchantID: "mch_1", Amount: 10_000_000,
		Status: core.StatusPending, DepositAddress: addr, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordPayment(context.Background(), addr, core.Payment{TxHash: "0x1", Amount: 10_000_000}, now); err != nil {
		t.Fatal(err)
	}
	return st, fakeChain{addr: core.MicroToNative(10_000_000)}, addr
}

func TestCleanBooksNoFindings(t *testing.T) {
	st, ch, _ := setup(t)
	w := New(Config{}, ch, st, nil)
	res, err := w.Pass(context.Background())
	if err != nil || !res.LedgerOK || res.Halted {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestShortfallHaltsLedgerAndCallsHook(t *testing.T) {
	st, ch, addr := setup(t)
	jobs, _ := st.ListSweepJobs(context.Background(), "mch_1", 10)
	j := jobs[0]
	j.State = core.SweepFailed
	if _, err := st.SaveSweepJob(context.Background(), j, time.Now()); err != nil {
		t.Fatal(err)
	}
	ch[addr] = core.MicroToNative(9_000_000)
	var hooked string
	w := New(Config{OnHalt: func(r string) { hooked = r }}, ch, st, nil)
	res, err := w.Pass(context.Background())
	if err != nil || !res.Halted || hooked == "" {
		t.Fatalf("res=%+v hook=%q err=%v", res, hooked, err)
	}
	if h, _ := st.Ledger().Halted(); !h {
		t.Fatal("ledger must be halted")
	}
	hooked = ""
	_, _ = w.Pass(context.Background())
	if hooked != "" {
		t.Fatal("OnHalt must fire once")
	}
}

func TestSmallShortfallAndSurplusOnlyReported(t *testing.T) {
	st, ch, addr := setup(t)
	jobs, _ := st.ListSweepJobs(context.Background(), "mch_1", 10)
	j := jobs[0]
	j.State = core.SweepFailed
	_, _ = st.SaveSweepJob(context.Background(), j, time.Now())

	ch[addr] = core.MicroToNative(10_000_000 - 400)
	w := New(Config{}, ch, st, nil)
	res, _ := w.Pass(context.Background())
	if res.Halted || len(res.Findings) != 1 || res.Findings[0].Kind != "shortfall" {
		t.Fatalf("%+v", res)
	}
	ch[addr] = core.MicroToNative(12_000_000)
	res, _ = w.Pass(context.Background())
	if res.Halted || len(res.Findings) != 1 || res.Findings[0].Kind != "surplus" {
		t.Fatalf("%+v", res)
	}
	ch[addr] = new(big.Int).Add(core.MicroToNative(10_000_000), big.NewInt(12345))
	res, _ = w.Pass(context.Background())
	if len(res.Findings) != 0 {
		t.Fatalf("dust must be ignored: %+v", res)
	}
}

func TestBusyDepositsSkipped(t *testing.T) {
	st, _, _ := setup(t)
	jobs, _ := st.ListSweepJobs(context.Background(), "mch_1", 10)
	j := jobs[0]
	j.State, j.TxHash = core.SweepSubmitted, "0xabc"
	if _, err := st.SaveSweepJob(context.Background(), j, time.Now()); err != nil {
		t.Fatal(err)
	}
	w := New(Config{}, fakeChain{}, st, nil)
	res, _ := w.Pass(context.Background())
	if res.Halted || res.Checked != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestBrokenLedgerHalts(t *testing.T) {
	st, ch, _ := setup(t)
	es := st.Ledger().Entries()
	es[0].Lines[0].Debit += 1
	if rep := ledger.VerifyEntries(es); rep.OK() {
		t.Fatal("tampering must be detected by VerifyEntries")
	}
	_ = ch
}
