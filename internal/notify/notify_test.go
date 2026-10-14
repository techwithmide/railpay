package notify

import (
	"arcpay/internal/core"
	"arcpay/internal/store"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type testSender struct {
	sent []Message
	fail error
}

func (s *testSender) Send(_ context.Context, m Message) error {
	if s.fail != nil {
		return s.fail
	}
	s.sent = append(s.sent, m)
	return nil
}

func TestRenderReceipt(t *testing.T) {
	e := core.Email{
		ID:         "eml_1",
		Kind:       core.EmailPaymentReceipt,
		To:         "buyer@example.com",
		MerchantID: "mch_1",
		IntentID:   "pi_1",
		Data: map[string]string{
			"merchant_name": "Acme Corp",
			"amount":        "25.00",
			"currency":      "USDC",
			"intent_id":     "pi_1",
			"paid_at":       "Sun, 12 Oct 2026 21:00:00 UTC",
			"tx_hash":       "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			"reference":     "INV-999",
		},
	}
	cfg := RenderConfig{Brand: "RailPay", ExplorerURL: "https://testnet.arcscan.io"}
	msg, err := Render(e, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.To != "buyer@example.com" {
		t.Errorf("expected recipient buyer@example.com, got %s", msg.To)
	}
	if !strings.Contains(msg.Subject, "25.00 USDC paid to Acme Corp") {
		t.Errorf("unexpected subject: %s", msg.Subject)
	}
	if !strings.Contains(strings.ToLower(msg.Text), "payment received") || !strings.Contains(msg.Text, "INV-999") {
		t.Errorf("unexpected text body: %s", msg.Text)
	}
	if !strings.Contains(msg.HTML, "<!doctype html>") || !strings.Contains(msg.HTML, "Acme Corp") {
		t.Errorf("unexpected html body: %s", msg.HTML)
	}
}

func TestRenderPayout(t *testing.T) {
	e := core.Email{
		ID:         "eml_2",
		Kind:       core.EmailPayoutSent,
		To:         "merchant@example.com",
		MerchantID: "mch_1",
		IntentID:   "pi_1",
		Data: map[string]string{
			"merchant_name":  "Acme Corp",
			"amount":         "24.95",
			"network_fee":    "0.05",
			"payment_amount": "25.00",
			"currency":       "USDC",
			"destination":    "0xce768c895e4be936db7dea5f53ad3b60ad3c3456",
			"tx_hash":        "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			"intent_id":      "pi_1",
		},
	}
	cfg := RenderConfig{Brand: "RailPay", ExplorerURL: "https://testnet.arcscan.io"}
	msg, err := Render(e, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.To != "merchant@example.com" {
		t.Errorf("expected merchant recipient, got %s", msg.To)
	}
	if !strings.Contains(msg.Subject, "Payout sent: 24.95 USDC") {
		t.Errorf("unexpected subject: %s", msg.Subject)
	}
	if !strings.Contains(msg.Text, "0xce768c895e4be936db7dea5f53ad3b60ad3c3456") {
		t.Errorf("destination missing in text: %s", msg.Text)
	}
}

func TestWorkerLifecycle(t *testing.T) {
	st := store.NewMemory()
	now := time.Now().UTC()
	st.SeedMerchant(core.Merchant{ID: "mch_test", Name: "Test Co", Email: "test@example.com"}, "test_key")

	// Trigger a payment in memory with CustomerEmail set
	in, _, err := st.CreateIntent(context.Background(), &core.Intent{
		ID: "pi_test", MerchantID: "mch_test", Amount: 10_000_000, CustomerEmail: "customer@domain.com",
		DepositAddress: "0x1111111111111111111111111111111111111111", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}, "")
	if err != nil {
		t.Fatalf("CreateIntent failed: %v", err)
	}

	applied, err := st.RecordPayment(context.Background(), in.DepositAddress, core.Payment{
		IntentID: in.ID, TxHash: "0xdeadbeef", Amount: 10_000_000,
	}, now)
	if err != nil || !applied {
		t.Fatalf("RecordPayment failed: %v", err)
	}

	// Verify email was enqueued into memory store
	ems, err := st.ListEmails(context.Background(), "mch_test", 10)
	if err != nil || len(ems) != 1 {
		t.Fatalf("expected 1 enqueued email, got %d (err: %v)", len(ems), err)
	}
	if ems[0].To != "customer@domain.com" || ems[0].Kind != core.EmailPaymentReceipt {
		t.Errorf("unexpected enqueued email: %+v", ems[0])
	}

	// Run worker once to send
	sender := &testSender{}
	w := &Worker{
		Store:  st,
		Sender: sender,
		Render: RenderConfig{Brand: "RailPay"},
		Now:    func() time.Time { return now },
	}

	n, err := w.RunOnce(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("RunOnce failed: n=%d, err=%v", n, err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(sender.sent))
	}
	if sender.sent[0].To != "customer@domain.com" {
		t.Errorf("expected email to customer@domain.com, got %s", sender.sent[0].To)
	}

	// Check email marked as sent in store
	ems, err = st.ListEmails(context.Background(), "mch_test", 10)
	if err != nil || len(ems) != 1 || ems[0].SentAt == nil {
		t.Errorf("expected email to be marked sent, got %+v", ems)
	}
}

func TestWorkerRetry(t *testing.T) {
	st := store.NewMemory()
	now := time.Now().UTC()
	st.SeedMerchant(core.Merchant{ID: "mch_retry", Name: "Retry Co", Email: "owner@domain.com"}, "key")

	in, _, _ := st.CreateIntent(context.Background(), &core.Intent{
		ID: "pi_retry", MerchantID: "mch_retry", Amount: 5_000_000, CustomerEmail: "cust@domain.com",
		DepositAddress: "0x2222222222222222222222222222222222222222", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}, "")
	_, _ = st.RecordPayment(context.Background(), in.DepositAddress, core.Payment{
		IntentID: in.ID, TxHash: "0xcafe", Amount: 5_000_000,
	}, now)

	// Sender fails transiently
	sender := &testSender{fail: errors.New("smtp connection refused")}
	w := &Worker{
		Store:  st,
		Sender: sender,
		Now:    func() time.Time { return now },
	}

	n, err := w.RunOnce(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("RunOnce failed: n=%d err=%v", n, err)
	}

	ems, _ := st.ListEmails(context.Background(), "mch_retry", 10)
	if len(ems) != 1 || ems[0].Attempts != 1 || ems[0].SentAt != nil || ems[0].Dead {
		t.Errorf("expected email to be scheduled for retry, got %+v", ems[0])
	}
}
