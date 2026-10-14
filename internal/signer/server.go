package signer

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

const (
	ScopeAddress  = "address"
	ScopeSign     = "sign"
	ScopeRegister = "register"
	ScopeApprove  = "approve"
)

type Tokens map[string]string

type Server struct {
	G      *Guard
	Tokens Tokens
}

func (s *Server) allowed(r *http.Request, scopes ...string) (scope string, ok bool) {
	got, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || got == "" {
		return "", false
	}
	for _, sc := range scopes {
		want := s.Tokens[sc]
		if want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			return sc, true
		}
	}
	return "", false
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/address", s.guard(s.address, ScopeAddress))
	mux.HandleFunc("POST /v1/sign", s.guard(s.sign, ScopeSign))
	mux.HandleFunc("POST /v1/destinations", s.guard(s.register, ScopeRegister))
	mux.HandleFunc("GET /v1/destinations/{merchant}", s.guard(s.getDest, ScopeRegister, ScopeApprove, ScopeSign))
	mux.HandleFunc("DELETE /v1/destinations/{merchant}/pending", s.guard(s.cancel, ScopeRegister, ScopeApprove))
	mux.HandleFunc("POST /v1/destinations/approve", s.guard(s.approve, ScopeApprove))
	mux.HandleFunc("POST /v1/freeze", s.guard(s.freeze, ScopeApprove))
	mux.HandleFunc("POST /v1/unfreeze", s.guard(s.unfreeze, ScopeApprove))
	mux.HandleFunc("GET /v1/audit", s.guard(s.audit, ScopeApprove))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	return mux
}

type handler func(w http.ResponseWriter, r *http.Request, scope string)

func (s *Server) guard(h handler, scopes ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sc, ok := s.allowed(r, scopes...)
		if !ok {
			jerr(w, http.StatusUnauthorized, "missing or invalid token for this endpoint")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		h(w, r, sc)
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		jerr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func jout(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jerr(w http.ResponseWriter, status int, msg string) {
	jout(w, status, map[string]any{"error": map[string]string{"message": msg}})
}

func fail(w http.ResponseWriter, err error) {
	var pe *PolicyError
	if errors.As(err, &pe) {
		jerr(w, http.StatusForbidden, pe.Error())
		return
	}
	jerr(w, http.StatusBadRequest, err.Error())
}

func (s *Server) address(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		MerchantID string `json:"merchant_id"`
		IntentID   string `json:"intent_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	a, err := s.G.Address(r.Context(), req.MerchantID, req.IntentID)
	if err != nil {
		fail(w, err)
		return
	}
	jout(w, http.StatusOK, map[string]string{"address": a})
}

func (s *Server) sign(w http.ResponseWriter, r *http.Request, _ string) {
	var req SignRequest
	if !decode(w, r, &req) {
		return
	}
	res, err := s.G.Sign(r.Context(), req)
	if err != nil {
		fail(w, err)
		return
	}
	jout(w, http.StatusOK, res)
}

func (s *Server) register(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		MerchantID  string `json:"merchant_id"`
		Address     string `json:"address"`
		RequestedBy string `json:"requested_by"`
	}
	if !decode(w, r, &req) {
		return
	}
	d, err := s.G.RegisterDestination(r.Context(), req.MerchantID, req.Address, req.RequestedBy)
	if err != nil {
		fail(w, err)
		return
	}
	jout(w, http.StatusOK, d)
}

func (s *Server) getDest(w http.ResponseWriter, r *http.Request, _ string) {
	d, _ := s.G.Destination(r.Context(), r.PathValue("merchant"))
	jout(w, http.StatusOK, d)
}

func (s *Server) cancel(w http.ResponseWriter, r *http.Request, sc string) {
	d, _ := s.G.CancelPending(r.PathValue("merchant"), sc)
	jout(w, http.StatusOK, d)
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		MerchantID string `json:"merchant_id"`
		Address    string `json:"address"`
		ApprovedBy string `json:"approved_by"`
	}
	if !decode(w, r, &req) {
		return
	}
	d, err := s.G.ApproveDestination(req.MerchantID, req.Address, req.ApprovedBy)
	if err != nil {
		fail(w, err)
		return
	}
	jout(w, http.StatusOK, d)
}

func (s *Server) freeze(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		Reason string `json:"reason"`
		By     string `json:"by"`
	}
	if !decode(w, r, &req) {
		return
	}
	s.G.Freeze(req.Reason, req.By)
	jout(w, http.StatusOK, map[string]bool{"frozen": true})
}

func (s *Server) unfreeze(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		By string `json:"by"`
	}
	if !decode(w, r, &req) {
		return
	}
	s.G.Unfreeze(req.By)
	jout(w, http.StatusOK, map[string]bool{"frozen": false})
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request, _ string) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 || n > 500 {
		n = 100
	}
	jout(w, http.StatusOK, map[string]any{"records": s.G.Audit(n)})
}
