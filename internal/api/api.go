package api

import (
	"arcpay/internal/core"
	"arcpay/internal/store"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type AddressProvider interface {
	Address(ctx context.Context, merchantID, intentID string) (string, error)
}

type Server struct {
	Store      store.Store
	Addresses  AddressProvider
	BaseURL    string
	DefaultTTL time.Duration
	Now        func() time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/payment_intents", s.createIntent)
	mux.HandleFunc("GET /v1/payment_intents/{id}", s.getIntent)
	mux.HandleFunc("GET /pay/{id}", s.checkoutIntent)
	mux.HandleFunc("GET /pay/{id}/status", s.checkoutStatus)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	return mux
}

type intentResponse struct {
	core.IntentView
	CheckoutURL string `json:"checkout_url"`
}

func (s *Server) respond(in *core.Intent) intentResponse {
	return intentResponse{IntentView: in.View(), CheckoutURL: strings.TrimRight(s.BaseURL, "/") + "/pay/" + in.ID}
}

func (s *Server) auth(r *http.Request) (core.Merchant, bool) {
	key, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || key == "" {
		return core.Merchant{}, false
	}
	m, err := s.Store.MerchantByAPIKey(r.Context(), key)
	return m, err == nil
}

func (s *Server) createIntent(w http.ResponseWriter, r *http.Request) {
	m, ok := s.auth(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "invalid API key")
		return
	}
	var req struct {
		Amount           string            `json:"amount"`
		ExpiresInSeconds int               `json:"expires_in_seconds"`
		CustomerEmail    string            `json:"customer_email"`
		Metadata         map[string]string `json:"metadata"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	var customerEmail string
	if req.CustomerEmail != "" {
		ce, err := core.ValidEmail(req.CustomerEmail)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "customer_email is invalid")
			return
		}
		customerEmail = ce
	}
	amount, err := core.ParseUSDC(req.Amount)
	if err != nil || amount == 0 {
		writeErr(w, http.StatusBadRequest, `"amount" must be a positive decimal string such as "25.00" (USDC, max 6 decimals)`)
		return
	}
	ttl := s.DefaultTTL
	if ttl == 0 {
		ttl = 30 * time.Minute
	}
	if req.ExpiresInSeconds != 0 {
		if req.ExpiresInSeconds < 60 || req.ExpiresInSeconds > 86400 {
			writeErr(w, http.StatusBadRequest, `"expires_in_seconds" must be between 60 and 86400`)
			return
		}
		ttl = time.Duration(req.ExpiresInSeconds) * time.Second
	}
	if len(req.Metadata) > 20 {
		writeErr(w, http.StatusBadRequest, "metadata: at most 20 keys")
		return
	}
	for k, v := range req.Metadata {
		if len(k) == 0 || len(k) > 40 || len(v) > 500 {
			writeErr(w, http.StatusBadRequest, "metadata: keys up to 40 chars, values up to 500")
			return
		}
	}

	id := core.NewID("pi")
	addr, err := s.Addresses.Address(r.Context(), m.ID, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not allocate deposit address")
		return
	}
	now := s.now()
	got, created, err := s.Store.CreateIntent(r.Context(), &core.Intent{
		ID: id, MerchantID: m.ID, Amount: amount, Status: core.StatusPending,
		DepositAddress: strings.ToLower(addr), FeeBps: m.FeeBps, CustomerEmail: customerEmail, Metadata: req.Metadata,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}, r.Header.Get("Idempotency-Key"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create payment intent")
		return
	}
	status := http.StatusCreated
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, s.respond(got))
}

func (s *Server) getIntent(w http.ResponseWriter, r *http.Request) {
	m, ok := s.auth(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "invalid API key")
		return
	}
	in, err := s.Store.GetIntent(r.Context(), r.PathValue("id"))
	if err != nil || in.MerchantID != m.ID {
		writeErr(w, http.StatusNotFound, "payment intent not found")
		return
	}
	writeJSON(w, http.StatusOK, s.respond(in))
}

func (s *Server) checkoutStatus(w http.ResponseWriter, r *http.Request) {
	in, err := s.Store.GetIntent(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": string(in.Status), "amount_received": core.FormatUSDC(in.Received)})
}

func (s *Server) checkoutIntent(w http.ResponseWriter, r *http.Request) {
	in, err := s.Store.GetIntent(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, s.respond(in))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"message": msg}})
}
