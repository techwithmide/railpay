package api

import (
	"arcpay/internal/core"
	"arcpay/internal/store"
	"arcpay/internal/wallet"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type localAddrs struct{ secret string }

func (l localAddrs) Address(_ context.Context, merchantID, intentID string) (string, error) {
	return wallet.Address(l.secret, merchantID, intentID)
}

func setup(t *testing.T) (*httptest.Server, *store.Memory) {
	st := store.NewMemory()
	st.SeedMerchant(core.Merchant{ID: "mch_1", FeeBps: 100}, "sk_test")
	st.SeedMerchant(core.Merchant{ID: "mch_2"}, "sk_other")
	srv := httptest.NewServer((&Server{Store: st, Addresses: localAddrs{"seed-seed-seed-seed-seed-seed-seed-1"}, BaseURL: "https://pay.example"}).Handler())
	t.Cleanup(srv.Close)
	return srv, st
}

func do(t *testing.T, method, url, key, body string, hdr map[string]string) (*http.Response, map[string]any) {
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func TestCreateGetAndPay(t *testing.T) {
	srv, st := setup(t)

	resp, out := do(t, "POST", srv.URL+"/v1/payment_intents", "sk_test", `{"amount":"25.50","metadata":{"order_id":"A1"}}`, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %v", resp.StatusCode, out)
	}
	id, addr := out["id"].(string), out["deposit_address"].(string)
	if out["amount"] != "25.500000" || out["status"] != "pending" || out["network"] != "arc" ||
		out["checkout_url"] != "https://pay.example/pay/"+id || !strings.HasPrefix(addr, "0x") || len(addr) != 42 {
		t.Fatalf("bad create response: %v", out)
	}

	if ok, err := st.RecordPayment(context.Background(), addr, core.Payment{TxHash: "0x1", Amount: 25_500_000}, time.Now()); err != nil || !ok {
		t.Fatalf("record: %v %v", ok, err)
	}
	_, out = do(t, "GET", srv.URL+"/v1/payment_intents/"+id, "sk_test", "", nil)
	if out["status"] != "paid" || out["amount_received"] != "25.500000" {
		t.Fatalf("not paid: %v", out)
	}
	_, out = do(t, "GET", srv.URL+"/pay/"+id+"/status", "", "", nil)
	if out["status"] != "paid" {
		t.Fatalf("public status: %v", out)
	}
}

func TestAuthAndOwnership(t *testing.T) {
	srv, _ := setup(t)
	if resp, _ := do(t, "POST", srv.URL+"/v1/payment_intents", "", `{"amount":"1"}`, nil); resp.StatusCode != 401 {
		t.Fatalf("no key: %d", resp.StatusCode)
	}
	_, out := do(t, "POST", srv.URL+"/v1/payment_intents", "sk_test", `{"amount":"1"}`, nil)
	id := out["id"].(string)
	if resp, _ := do(t, "GET", srv.URL+"/v1/payment_intents/"+id, "sk_other", "", nil); resp.StatusCode != 404 {
		t.Fatalf("other merchant's intent must be 404, got %d", resp.StatusCode)
	}
}

func TestValidationAndIdempotency(t *testing.T) {
	srv, _ := setup(t)
	for _, body := range []string{`{"amount":"0"}`, `{"amount":"abc"}`, `{"amount":"1.0000001"}`, `{"amount":"1","expires_in_seconds":5}`, `{"amount":"1","bogus":true}`} {
		if resp, _ := do(t, "POST", srv.URL+"/v1/payment_intents", "sk_test", body, nil); resp.StatusCode != 400 {
			t.Errorf("%s: want 400 got %d", body, resp.StatusCode)
		}
	}
	h := map[string]string{"Idempotency-Key": "order-42"}
	r1, o1 := do(t, "POST", srv.URL+"/v1/payment_intents", "sk_test", `{"amount":"5"}`, h)
	r2, o2 := do(t, "POST", srv.URL+"/v1/payment_intents", "sk_test", `{"amount":"5"}`, h)
	if r1.StatusCode != 201 || r2.StatusCode != 200 || o1["id"] != o2["id"] || o1["deposit_address"] != o2["deposit_address"] {
		t.Fatalf("idempotency broken: %d/%d %v %v", r1.StatusCode, r2.StatusCode, o1["id"], o2["id"])
	}
}

func TestCheckoutIntentJSON(t *testing.T) {
	srv, _ := setup(t)
	_, out := do(t, "POST", srv.URL+"/v1/payment_intents", "sk_test", `{"amount":"7.25"}`, nil)
	resp, body := do(t, "GET", srv.URL+"/pay/"+out["id"].(string), "", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("checkout endpoint want 200, got %d: %v", resp.StatusCode, body)
	}
	if body["amount"] != "7.250000" || body["deposit_address"] != out["deposit_address"] {
		t.Fatalf("checkout json missing amount or address: %v", body)
	}
}
