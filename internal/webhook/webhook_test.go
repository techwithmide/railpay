package webhook

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"arcpay/internal/core"
	"arcpay/internal/store"
)

func TestSignVerify(t *testing.T) {
	body := []byte(`{"a":1}`)
	now := time.Unix(1_700_000_000, 0)
	h := Sign("whsec", now.Unix(), body)
	if err := Verify("whsec", h, body, time.Minute, now); err != nil {
		t.Fatal(err)
	}
	if Verify("other", h, body, time.Minute, now) == nil {
		t.Error("wrong secret accepted")
	}
	if Verify("whsec", h, []byte(`{"a":2}`), time.Minute, now) == nil {
		t.Error("tampered body accepted")
	}
	if Verify("whsec", h, body, time.Minute, now.Add(time.Hour)) == nil {
		t.Error("stale timestamp accepted")
	}
}

func TestRetryThenDeliver(t *testing.T) {
	ctx := context.Background()
	var hits atomic.Int32
	var verifyErr atomic.Value
	clock := time.Unix(1_700_000_000, 0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := Verify("whsec", r.Header.Get("Arcpay-Signature"), body, time.Minute, clock); err != nil {
			verifyErr.Store(err)
		}
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	st := store.NewMemory()
	st.SeedMerchant(core.Merchant{ID: "mch_1", WebhookURL: srv.URL, WebhookSecret: "whsec"}, "k")
	_, _, _ = st.CreateIntent(ctx, &core.Intent{ID: "pi_1", MerchantID: "mch_1", Amount: 1_000_000, Status: core.StatusPending,
		DepositAddress: "0xabc", ExpiresAt: clock.Add(time.Hour)}, "")
	if _, err := st.RecordPayment(ctx, "0xabc", core.Payment{TxHash: "0x1", Amount: 1_000_000}, clock); err != nil {
		t.Fatal(err)
	}

	d := NewDispatcher(st, NewClient(true), slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.Now = func() time.Time { return clock }

	if n, _ := d.RunOnce(ctx); n != 1 || hits.Load() != 1 {
		t.Fatalf("first attempt: n=%d hits=%d", n, hits.Load())
	}
	if n, _ := d.RunOnce(ctx); n != 0 {
		t.Fatalf("retried too early: n=%d", n)
	}
	clock = clock.Add(6 * time.Second)
	if n, _ := d.RunOnce(ctx); n != 1 || hits.Load() != 2 {
		t.Fatalf("retry: n=%d hits=%d", n, hits.Load())
	}
	clock = clock.Add(time.Hour)
	if n, _ := d.RunOnce(ctx); n != 0 {
		t.Fatalf("delivered event should not be sent again: n=%d", n)
	}
	if v := verifyErr.Load(); v != nil {
		t.Fatalf("signature failed verification: %v", v)
	}
}

func TestDeadLetterAfterMaxAttempts(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	clock := time.Unix(1_700_000_000, 0)
	st := store.NewMemory()
	st.SeedMerchant(core.Merchant{ID: "m", WebhookURL: srv.URL, WebhookSecret: "s"}, "k")
	_, _, _ = st.CreateIntent(ctx, &core.Intent{ID: "pi_1", MerchantID: "m", Amount: 1, Status: core.StatusPending, DepositAddress: "0xabc", ExpiresAt: clock.Add(time.Hour)}, "")
	_, _ = st.RecordPayment(ctx, "0xabc", core.Payment{TxHash: "0x1", Amount: 1}, clock)

	d := NewDispatcher(st, NewClient(true), slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.MaxAttempts = 3
	d.Now = func() time.Time { return clock }
	for i := 0; i < 5; i++ {
		_, _ = d.RunOnce(ctx)
		clock = clock.Add(13 * time.Hour)
	}
	if ds, _ := st.LeaseDeliveries(ctx, clock.Add(1000*time.Hour), 10, time.Minute); len(ds) != 0 {
		t.Fatalf("dead delivery still leasable: %+v", ds)
	}
}

func TestClientBlocksInternalAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	if _, err := NewClient(false).Get(srv.URL); err == nil {
		t.Fatal("loopback target should be blocked")
	}
	if resp, err := NewClient(true).Get(srv.URL); err != nil {
		t.Fatalf("dev client should allow loopback: %v", err)
	} else {
		resp.Body.Close()
	}
}
