package signer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"arcpay/internal/eth"
)

type Backend interface {
	Address(merchantID, intentID string) (eth.Address, error)
	Sign(merchantID, intentID string, tx *eth.DynamicFeeTx) (*eth.SignedTx, error)
}

type SignRequest struct {
	MerchantID string `json:"merchant_id"`
	IntentID   string `json:"intent_id"`
	JobID      string `json:"job_id,omitempty"`
	ChainID    uint64 `json:"chain_id"`
	Nonce      uint64 `json:"nonce"`
	GasTipCap  string `json:"gas_tip_cap"`
	GasFeeCap  string `json:"gas_fee_cap"`
	Gas        uint64 `json:"gas"`
	To         string `json:"to"`
	Value      string `json:"value"`
	Data       string `json:"data,omitempty"`
}

type SignResult struct {
	Raw    string `json:"raw"`
	TxHash string `json:"tx_hash"`
	From   string `json:"from"`
}

type Destination struct {
	MerchantID    string    `json:"merchant_id"`
	Active        string    `json:"active,omitempty"`
	ActiveSince   time.Time `json:"active_since,omitempty"`
	Pending       string    `json:"pending,omitempty"`
	PendingAt     time.Time `json:"pending_requested_at,omitempty"`
	ActivatesAt   time.Time `json:"pending_activates_at,omitempty"`
	NeedsApproval bool      `json:"pending_needs_approval,omitempty"`
}

type Service interface {
	Address(ctx context.Context, merchantID, intentID string) (string, error)
	Sign(ctx context.Context, req SignRequest) (*SignResult, error)
	RegisterDestination(ctx context.Context, merchantID, address, requestedBy string) (Destination, error)
	Destination(ctx context.Context, merchantID string) (Destination, error)
}

type PolicyError struct{ Reason string }

func (e *PolicyError) Error() string { return "signer policy: " + e.Reason }

type Config struct {
	ChainID             uint64
	MaxValue            *big.Int
	DailyCap            *big.Int
	GlobalDailyCap      *big.Int
	MaxFeeCap           *big.Int
	MaxSignsPerIntent   int
	MaxSignsPerMinute   int
	DestinationCooldown time.Duration
	RequireApproval     bool
	Now                 func() time.Time
	OnChange            func(State)
	AuditSink           func(AuditRecord)
}

const transferGas = 21000

type destState struct {
	Active      string    `json:"active,omitempty"`
	ActiveSince time.Time `json:"active_since,omitempty"`
	Pending     string    `json:"pending,omitempty"`
	PendingAt   time.Time `json:"pending_at,omitempty"`
	ActivatesAt time.Time `json:"activates_at,omitempty"`
	Approved    bool      `json:"approved,omitempty"`
}

type issued struct {
	Address string `json:"address"`
	Signs   int    `json:"signs"`
}

type spend struct {
	At       time.Time `json:"at"`
	Merchant string    `json:"merchant"`
	Key      string    `json:"key"`
	Wei      string    `json:"wei"`
}

type State struct {
	Issued       map[string]issued    `json:"issued"`
	Dests        map[string]destState `json:"destinations"`
	Spends       []spend              `json:"spends"`
	Frozen       bool                 `json:"frozen"`
	FrozenReason string               `json:"frozen_reason,omitempty"`
	AuditHead    string               `json:"audit_head"`
	AuditSeq     uint64               `json:"audit_seq"`
}

type AuditRecord struct {
	Seq        uint64    `json:"seq"`
	At         time.Time `json:"at"`
	Action     string    `json:"action"`
	Outcome    string    `json:"outcome"`
	MerchantID string    `json:"merchant_id,omitempty"`
	IntentID   string    `json:"intent_id,omitempty"`
	JobID      string    `json:"job_id,omitempty"`
	Detail     string    `json:"detail,omitempty"`
	PrevHash   string    `json:"prev_hash"`
	Hash       string    `json:"hash"`
}

type Guard struct {
	cfg Config
	be  Backend

	mu       sync.Mutex
	st       State
	recent   []time.Time
	auditLog []AuditRecord
}

func NewGuard(cfg Config, be Backend, restore *State) (*Guard, error) {
	if cfg.MaxValue == nil || cfg.MaxValue.Sign() <= 0 {
		return nil, errors.New("signer: MaxValue is required")
	}
	if cfg.MaxFeeCap == nil || cfg.MaxFeeCap.Sign() <= 0 {
		return nil, errors.New("signer: MaxFeeCap is required")
	}
	if cfg.ChainID == 0 {
		return nil, errors.New("signer: ChainID is required")
	}
	if cfg.MaxSignsPerIntent == 0 {
		cfg.MaxSignsPerIntent = 10
	}
	if cfg.MaxSignsPerMinute == 0 {
		cfg.MaxSignsPerMinute = 120
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	g := &Guard{cfg: cfg, be: be}
	g.st = State{Issued: map[string]issued{}, Dests: map[string]destState{}}
	if restore != nil {
		g.st = *restore
		if g.st.Issued == nil {
			g.st.Issued = map[string]issued{}
		}
		if g.st.Dests == nil {
			g.st.Dests = map[string]destState{}
		}
	}
	return g, nil
}

func key2(a, b string) string { return a + "|" + b }

func (g *Guard) Snapshot() State {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.snapshotLocked()
}

func (g *Guard) snapshotLocked() State {
	s := g.st
	s.Issued = make(map[string]issued, len(g.st.Issued))
	for k, v := range g.st.Issued {
		s.Issued[k] = v
	}
	s.Dests = make(map[string]destState, len(g.st.Dests))
	for k, v := range g.st.Dests {
		s.Dests[k] = v
	}
	s.Spends = append([]spend(nil), g.st.Spends...)
	return s
}

func (g *Guard) changedLocked() {
	if g.cfg.OnChange != nil {
		g.cfg.OnChange(g.snapshotLocked())
	}
}

func (g *Guard) auditLocked(action, outcome, merchant, intent, job, detail string) {
	now := g.cfg.Now().UTC()
	r := AuditRecord{Seq: g.st.AuditSeq + 1, At: now, Action: action, Outcome: outcome,
		MerchantID: merchant, IntentID: intent, JobID: job, Detail: detail, PrevHash: g.st.AuditHead}
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s|%s", r.Seq, r.At.Format(time.RFC3339Nano),
		r.Action, r.Outcome, r.MerchantID, r.IntentID, r.JobID, r.Detail, r.PrevHash)))
	r.Hash = hex.EncodeToString(h[:])
	g.st.AuditSeq, g.st.AuditHead = r.Seq, r.Hash
	g.auditLog = append(g.auditLog, r)
	if len(g.auditLog) > 5000 {
		g.auditLog = g.auditLog[len(g.auditLog)-5000:]
	}
	if g.cfg.AuditSink != nil {
		g.cfg.AuditSink(r)
	}
}

func (g *Guard) Audit(limit int) []AuditRecord {
	g.mu.Lock()
	defer g.mu.Unlock()
	if limit <= 0 || limit > len(g.auditLog) {
		limit = len(g.auditLog)
	}
	return append([]AuditRecord(nil), g.auditLog[len(g.auditLog)-limit:]...)
}

func (g *Guard) Address(_ context.Context, merchantID, intentID string) (string, error) {
	if merchantID == "" || intentID == "" {
		return "", errors.New("signer: merchant_id and intent_id are required")
	}
	a, err := g.be.Address(merchantID, intentID)
	if err != nil {
		return "", err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	k := key2(merchantID, intentID)
	if cur, ok := g.st.Issued[k]; ok {
		return cur.Address, nil
	}
	g.st.Issued[k] = issued{Address: a.Lower()}
	g.auditLocked("address.issue", "info", merchantID, intentID, "", a.Lower())
	g.changedLocked()
	return a.Lower(), nil
}

func (g *Guard) validDestination(addr string) (eth.Address, error) {
	a, err := eth.ParseAddress(strings.TrimSpace(addr))
	if err != nil {
		return a, err
	}
	if a.IsZero() {
		return a, errors.New("the zero address is not a valid destination")
	}
	if strings.EqualFold(a.Lower(), "0xfffffffffffffffffffffffffffffffffffffffe") {
		return a, errors.New("system addresses are not valid destinations")
	}
	for _, v := range g.st.Issued {
		if v.Address == a.Lower() {
			return a, errors.New("a deposit address cannot be a settlement destination")
		}
	}
	return a, nil
}

func (g *Guard) promoteLocked(merchant string) {
	d, ok := g.st.Dests[merchant]
	if !ok || d.Pending == "" {
		return
	}
	now := g.cfg.Now()
	if now.Before(d.ActivatesAt) || (g.cfg.RequireApproval && !d.Approved) {
		return
	}
	g.auditLocked("destination.activate", "info", merchant, "", "", d.Pending)
	d.Active, d.ActiveSince = d.Pending, now.UTC()
	d.Pending, d.PendingAt, d.ActivatesAt, d.Approved = "", time.Time{}, time.Time{}, false
	g.st.Dests[merchant] = d
	g.changedLocked()
}

func (g *Guard) destView(merchant string) Destination {
	d := g.st.Dests[merchant]
	return Destination{MerchantID: merchant, Active: d.Active, ActiveSince: d.ActiveSince,
		Pending: d.Pending, PendingAt: d.PendingAt, ActivatesAt: d.ActivatesAt,
		NeedsApproval: d.Pending != "" && g.cfg.RequireApproval && !d.Approved}
}

func (g *Guard) RegisterDestination(_ context.Context, merchantID, address, requestedBy string) (Destination, error) {
	if merchantID == "" {
		return Destination{}, errors.New("signer: merchant_id is required")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	a, err := g.validDestination(address)
	if err != nil {
		g.auditLocked("destination.register", "deny", merchantID, "", "", err.Error())
		return Destination{}, &PolicyError{Reason: err.Error()}
	}
	d := g.st.Dests[merchantID]
	addr := a.Lower()
	switch {
	case d.Active == addr && d.Pending == "":
		return g.destView(merchantID), nil
	case d.Active == addr:
		d.Pending, d.PendingAt, d.ActivatesAt, d.Approved = "", time.Time{}, time.Time{}, false
	case d.Pending == addr:
		return g.destView(merchantID), nil
	default:
		now := g.cfg.Now().UTC()
		d.Pending, d.PendingAt, d.ActivatesAt, d.Approved = addr, now, now.Add(g.cfg.DestinationCooldown), false
	}
	g.st.Dests[merchantID] = d
	g.auditLocked("destination.register", "info", merchantID, "", "", fmt.Sprintf("%s by %s", addr, requestedBy))
	g.promoteLocked(merchantID)
	g.changedLocked()
	return g.destView(merchantID), nil
}

func (g *Guard) ApproveDestination(merchantID, address, approvedBy string) (Destination, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	a, err := eth.ParseAddress(strings.TrimSpace(address))
	if err != nil {
		return Destination{}, &PolicyError{Reason: err.Error()}
	}
	d := g.st.Dests[merchantID]
	if d.Pending == "" || d.Pending != a.Lower() {
		g.auditLocked("destination.approve", "deny", merchantID, "", "", "no matching pending address")
		return Destination{}, &PolicyError{Reason: "no matching pending address"}
	}
	d.Approved = true
	g.st.Dests[merchantID] = d
	g.auditLocked("destination.approve", "info", merchantID, "", "", fmt.Sprintf("%s by %s", d.Pending, approvedBy))
	g.promoteLocked(merchantID)
	g.changedLocked()
	return g.destView(merchantID), nil
}

func (g *Guard) CancelPending(merchantID, by string) (Destination, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	d := g.st.Dests[merchantID]
	if d.Pending != "" {
		g.auditLocked("destination.cancel", "info", merchantID, "", "", fmt.Sprintf("%s by %s", d.Pending, by))
		d.Pending, d.PendingAt, d.ActivatesAt, d.Approved = "", time.Time{}, time.Time{}, false
		g.st.Dests[merchantID] = d
		g.changedLocked()
	}
	return g.destView(merchantID), nil
}

func (g *Guard) Destination(_ context.Context, merchantID string) (Destination, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.promoteLocked(merchantID)
	return g.destView(merchantID), nil
}

func (g *Guard) Freeze(reason, by string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.st.Frozen {
		g.st.Frozen, g.st.FrozenReason = true, reason
		g.auditLocked("freeze", "info", "", "", "", reason+" by "+by)
		g.changedLocked()
	}
}

func (g *Guard) Unfreeze(by string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.st.Frozen {
		g.st.Frozen, g.st.FrozenReason = false, ""
		g.auditLocked("unfreeze", "info", "", "", "", "by "+by)
		g.changedLocked()
	}
}

func parseWei(s, name string) (*big.Int, error) {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() < 0 {
		return nil, fmt.Errorf("%s must be a non-negative decimal integer", name)
	}
	return v, nil
}

func (g *Guard) windowTotalsLocked(now time.Time, merchant, skipKey, skipMerchant string) (m, all *big.Int) {
	m, all = new(big.Int), new(big.Int)
	cutoff := now.Add(-24 * time.Hour)
	keep := g.st.Spends[:0]
	for _, sp := range g.st.Spends {
		if sp.At.Before(cutoff) {
			continue
		}
		keep = append(keep, sp)
		if sp.Key == skipKey && sp.Merchant == skipMerchant {
			continue
		}
		w, _ := new(big.Int).SetString(sp.Wei, 10)
		all.Add(all, w)
		if sp.Merchant == merchant {
			m.Add(m, w)
		}
	}
	g.st.Spends = keep
	return m, all
}

func (g *Guard) deny(req SignRequest, reason string) (*SignResult, error) {
	g.auditLocked("sign", "deny", req.MerchantID, req.IntentID, req.JobID, reason)
	return nil, &PolicyError{Reason: reason}
}

func (g *Guard) Sign(_ context.Context, req SignRequest) (*SignResult, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.cfg.Now()

	if g.st.Frozen {
		return g.deny(req, "signer is frozen: "+g.st.FrozenReason)
	}
	iss, ok := g.st.Issued[key2(req.MerchantID, req.IntentID)]
	if !ok {
		return g.deny(req, "unknown deposit: this signer did not issue an address for that merchant and intent")
	}
	if req.ChainID != g.cfg.ChainID {
		return g.deny(req, fmt.Sprintf("chain id %d is not %d", req.ChainID, g.cfg.ChainID))
	}
	if req.Gas != transferGas {
		return g.deny(req, fmt.Sprintf("gas must be exactly %d for a plain transfer", transferGas))
	}
	if d := strings.TrimPrefix(strings.TrimSpace(req.Data), "0x"); d != "" {
		return g.deny(req, "calldata is not allowed")
	}
	if req.Nonce > 64 {
		return g.deny(req, "nonce out of range for a single-purpose deposit address")
	}
	tip, err := parseWei(req.GasTipCap, "gas_tip_cap")
	if err != nil {
		return g.deny(req, err.Error())
	}
	feeCap, err := parseWei(req.GasFeeCap, "gas_fee_cap")
	if err != nil {
		return g.deny(req, err.Error())
	}
	value, err := parseWei(req.Value, "value")
	if err != nil {
		return g.deny(req, err.Error())
	}
	if feeCap.Cmp(g.cfg.MaxFeeCap) > 0 {
		return g.deny(req, "gas_fee_cap exceeds the fee ceiling")
	}
	if tip.Cmp(feeCap) > 0 {
		return g.deny(req, "gas_tip_cap exceeds gas_fee_cap")
	}
	if value.Sign() == 0 {
		return g.deny(req, "value must be positive")
	}
	if value.Cmp(g.cfg.MaxValue) > 0 {
		return g.deny(req, "value exceeds the per-transaction cap")
	}
	to, err := eth.ParseAddress(strings.TrimSpace(req.To))
	if err != nil {
		return g.deny(req, "invalid destination: "+err.Error())
	}
	g.promoteLocked(req.MerchantID)
	active := g.st.Dests[req.MerchantID].Active
	if active == "" {
		return g.deny(req, "merchant has no active settlement destination")
	}
	if to.Lower() != active {
		return g.deny(req, "destination is not the merchant's active settlement address")
	}
	if iss.Signs >= g.cfg.MaxSignsPerIntent {
		return g.deny(req, "signature budget for this deposit is exhausted")
	}
	cut := now.Add(-time.Minute)
	keep := g.recent[:0]
	for _, t := range g.recent {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	g.recent = keep
	if len(g.recent) >= g.cfg.MaxSignsPerMinute {
		return g.deny(req, "rate limit exceeded")
	}
	sk := key2(req.IntentID, fmt.Sprint(req.Nonce))
	mTot, allTot := g.windowTotalsLocked(now, req.MerchantID, sk, req.MerchantID)
	if g.cfg.DailyCap != nil && g.cfg.DailyCap.Sign() > 0 && new(big.Int).Add(mTot, value).Cmp(g.cfg.DailyCap) > 0 {
		return g.deny(req, "merchant 24h cap exceeded")
	}
	if g.cfg.GlobalDailyCap != nil && g.cfg.GlobalDailyCap.Sign() > 0 && new(big.Int).Add(allTot, value).Cmp(g.cfg.GlobalDailyCap) > 0 {
		return g.deny(req, "global 24h cap exceeded")
	}

	tx := &eth.DynamicFeeTx{
		ChainID: new(big.Int).SetUint64(req.ChainID), Nonce: req.Nonce, GasTipCap: tip, GasFeeCap: feeCap,
		Gas: transferGas, To: to, Value: value,
	}
	signed, err := g.be.Sign(req.MerchantID, req.IntentID, tx)
	if err != nil {
		g.auditLocked("sign", "deny", req.MerchantID, req.IntentID, req.JobID, "backend error: "+err.Error())
		return nil, err
	}
	if signed.From.Lower() != iss.Address {
		g.auditLocked("sign", "deny", req.MerchantID, req.IntentID, req.JobID, "signature did not recover to the issued address")
		return nil, &PolicyError{Reason: "internal consistency check failed"}
	}
	iss.Signs++
	g.st.Issued[key2(req.MerchantID, req.IntentID)] = iss
	g.recent = append(g.recent, now)
	rest := g.st.Spends[:0]
	for _, sp := range g.st.Spends {
		if sp.Key != sk || sp.Merchant != req.MerchantID {
			rest = append(rest, sp)
		}
	}
	g.st.Spends = append(rest, spend{At: now, Merchant: req.MerchantID, Key: sk, Wei: value.String()})
	g.auditLocked("sign", "allow", req.MerchantID, req.IntentID, req.JobID,
		fmt.Sprintf("to=%s value=%s nonce=%d tx=0x%x", to.Lower(), value, req.Nonce, signed.Hash))
	g.changedLocked()
	return &SignResult{Raw: "0x" + hex.EncodeToString(signed.Raw), TxHash: "0x" + hex.EncodeToString(signed.Hash[:]), From: iss.Address}, nil
}

var _ Service = (*Guard)(nil)
