package core

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

func TestParseFormatUSDC(t *testing.T) {
	ok := map[string]uint64{"25": 25_000_000, "25.5": 25_500_000, "0.000001": 1, ".5": 500_000, "1.": 1_000_000}
	for in, want := range ok {
		got, err := ParseUSDC(in)
		if err != nil || got != want {
			t.Errorf("ParseUSDC(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", ".", "-1", "+1", "1.0000001", "abc", "1.2.3", "99999999999999999999"} {
		if _, err := ParseUSDC(in); err == nil {
			t.Errorf("ParseUSDC(%q) should fail", in)
		}
	}
	if got := FormatUSDC(25_500_000); got != "25.500000" {
		t.Errorf("FormatUSDC = %s", got)
	}
}

func TestApplyPayment(t *testing.T) {
	now := time.Unix(1_000, 0)
	mk := func() *Intent {
		return &Intent{ID: "pi_1", Amount: 10_000_000, Status: StatusPending, ExpiresAt: now.Add(time.Minute)}
	}

	in := mk()
	if ev := in.ApplyPayment(4_000_000, now); ev != EventPartiallyPaid || in.Status != StatusPending {
		t.Fatalf("partial: %q %s", ev, in.Status)
	}
	if ev := in.ApplyPayment(6_000_000, now); ev != EventSucceeded || in.Status != StatusPaid || in.PaidAt == nil {
		t.Fatalf("complete: %q %s", ev, in.Status)
	}
	if ev := in.ApplyPayment(1_000_000, now); ev != "" || in.Received != 11_000_000 {
		t.Fatalf("extra after paid: %q received=%d", ev, in.Received)
	}

	in = mk()
	if !in.ExpireIfDue(now.Add(2 * time.Minute)) {
		t.Fatal("should expire")
	}
	if ev := in.ApplyPayment(10_000_000, now.Add(3*time.Minute)); ev != EventLatePayment || in.Status != StatusExpired {
		t.Fatalf("late: %q %s", ev, in.Status)
	}

	in = mk() // expiry sweep hasn't run yet
	if ev := in.ApplyPayment(10_000_000, now.Add(2*time.Minute)); ev != EventLatePayment || in.Status != StatusExpired {
		t.Fatalf("late before sweep: %q %s", ev, in.Status)
	}

	in = mk() // overpay in one transfer
	if ev := in.ApplyPayment(12_000_000, now); ev != EventSucceeded || in.Received != 12_000_000 {
		t.Fatalf("overpay: %q", ev)
	}
}

func TestUnitConversions(t *testing.T) {
	big18 := func(s string) *big.Int { v, _ := new(big.Int).SetString(s, 10); return v }
	cases := []struct {
		native      string
		floor, ceil uint64
	}{
		{"0", 0, 0},
		{"1", 0, 1},
		{"999999999999", 0, 1},
		{"1000000000000", 1, 1},
		{"1000000000001", 1, 2},
		{"25000000000000000000", 25_000_000, 25_000_000},
		{"4221000000000001", 4_221, 4_222},
	}
	for _, c := range cases {
		f, ok1 := NativeToMicro(big18(c.native))
		ce, ok2 := CeilNativeToMicro(big18(c.native))
		if !ok1 || !ok2 || f != c.floor || ce != c.ceil {
			t.Errorf("%s: floor=%d ceil=%d want %d/%d", c.native, f, ce, c.floor, c.ceil)
		}
	}
	if _, ok := NativeToMicro(big18("-1")); ok {
		t.Error("negative must fail")
	}
	if _, ok := NativeToMicro(nil); ok {
		t.Error("nil must fail")
	}
	huge := new(big.Int).Lsh(big.NewInt(1), 200)
	if _, ok := NativeToMicro(huge); ok {
		t.Error("overflow must fail")
	}
	if MicroToNative(25_000_000).String() != "25000000000000000000" {
		t.Error("MicroToNative wrong")
	}
	if m, _ := NativeToMicro(MicroToNative(123456789)); m != 123456789 {
		t.Error("round trip")
	}
}

func TestPayoutEventPayload(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	in := &Intent{ID: "pi_1", MerchantID: "m_1", Amount: 10, Status: StatusPaid, DepositAddress: "0xabc", ExpiresAt: now}
	job := &SweepJob{ID: "swp_1", Destination: "0xdef", ValueMicro: 9_995_000, ChargeMicro: 5_000, TxHash: "0xhash", State: SweepConfirmed, BlockNumber: 42}
	ev := NewPayoutEvent(EventPayoutDone, in, job, now)
	var body map[string]any
	if err := json.Unmarshal(ev.Payload, &body); err != nil {
		t.Fatal(err)
	}
	data := body["data"].(map[string]any)
	payout := data["payout"].(map[string]any)
	if body["type"] != "payout.completed" || payout["amount"] != "9.995000" || payout["network_fee"] != "0.005000" ||
		payout["tx_hash"] != "0xhash" || data["payment_intent"] == nil || data["payment"] != nil {
		t.Fatalf("payload: %s", ev.Payload)
	}
}
