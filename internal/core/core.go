package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	USDCDecimals = 6
	unit         = 1_000_000
	Currency     = "USDC"
	Network      = "arc"
)

type Merchant struct {
	ID                    string
	Name                  string
	Email                 string
	Status                string
	FeeBps                uint32
	SettlementAddress     string
	SettlementRequestedAt time.Time
	EmailOptOut           bool
	WebhookURL            string
	WebhookSecret         string
	CreatedAt             time.Time
}

type User struct {
	ID           string    `json:"id"`
	Provider     string    `json:"provider"`
	Subject      string    `json:"-"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	MerchantID   string    `json:"merchant_id"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

type APIKey struct {
	ID         string
	MerchantID string
	Name       string
	Prefix     string
	Hash       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

type Session struct {
	ID         string
	UserID     string
	MerchantID string
	CSRF       string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

type Status string

const (
	StatusPending Status = "pending"
	StatusPaid    Status = "paid"
	StatusExpired Status = "expired"
)

const (
	EventSucceeded     = "payment_intent.succeeded"
	EventPartiallyPaid = "payment_intent.partially_paid"
	EventExpired       = "payment_intent.expired"
	EventLatePayment   = "payment_intent.late_payment"
	EventPayoutDone    = "payout.completed"
	EventPayoutFailed  = "payout.failed"
)

type Intent struct {
	ID             string
	MerchantID     string
	Amount         uint64
	Received       uint64
	Status         Status
	DepositAddress string
	FeeBps         uint32
	CustomerEmail  string
	Metadata       map[string]string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	PaidAt         *time.Time
}

type Payment struct {
	IntentID    string
	TxHash      string
	LogIndex    uint64
	BlockNumber uint64
	From        string
	Amount      uint64
}

func (i *Intent) ApplyPayment(amount uint64, now time.Time) string {
	if sum := i.Received + amount; sum >= i.Received {
		i.Received = sum
	} else {
		i.Received = math.MaxUint64
	}
	switch i.Status {
	case StatusPaid:
		return ""
	case StatusExpired:
		return EventLatePayment
	}
	if now.After(i.ExpiresAt) {
		i.Status = StatusExpired
		return EventLatePayment
	}
	if i.Received >= i.Amount {
		t := now
		i.Status = StatusPaid
		i.PaidAt = &t
		return EventSucceeded
	}
	return EventPartiallyPaid
}

func (i *Intent) ExpireIfDue(now time.Time) bool {
	if i.Status == StatusPending && now.After(i.ExpiresAt) {
		i.Status = StatusExpired
		return true
	}
	return false
}

func (i *Intent) Clone() *Intent {
	c := *i
	c.Metadata = make(map[string]string, len(i.Metadata))
	for k, v := range i.Metadata {
		c.Metadata[k] = v
	}
	if i.PaidAt != nil {
		t := *i.PaidAt
		c.PaidAt = &t
	}
	return &c
}

type IntentView struct {
	ID             string            `json:"id"`
	Object         string            `json:"object"`
	Status         Status            `json:"status"`
	Amount         string            `json:"amount"`
	AmountReceived string            `json:"amount_received"`
	Currency       string            `json:"currency"`
	Network        string            `json:"network"`
	DepositAddress string            `json:"deposit_address"`
	CustomerEmail  string            `json:"customer_email,omitempty"`
	Metadata       map[string]string `json:"metadata"`
	CreatedAt      time.Time         `json:"created_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
	PaidAt         *time.Time        `json:"paid_at,omitempty"`
}

func (i *Intent) View() IntentView {
	md := i.Metadata
	if md == nil {
		md = map[string]string{}
	}
	return IntentView{
		ID:             i.ID,
		Object:         "payment_intent",
		Status:         i.Status,
		Amount:         FormatUSDC(i.Amount),
		AmountReceived: FormatUSDC(i.Received),
		Currency:       Currency,
		Network:        Network,
		DepositAddress: i.DepositAddress,
		CustomerEmail:  i.CustomerEmail,
		Metadata:       md,
		CreatedAt:      i.CreatedAt,
		ExpiresAt:      i.ExpiresAt,
		PaidAt:         i.PaidAt,
	}
}

type SweepState string

const (
	SweepQueued    SweepState = "queued"
	SweepSigned    SweepState = "signed"
	SweepSubmitted SweepState = "submitted"
	SweepConfirmed SweepState = "confirmed"
	SweepFailed    SweepState = "failed"
)

func (s SweepState) Active() bool { return s == SweepQueued || s == SweepSigned || s == SweepSubmitted }

type SweepJob struct {
	ID             string
	IntentID       string
	MerchantID     string
	DepositAddress string
	State          SweepState
	Version        uint64
	Attempts       int
	Reason         string
	LastError      string
	NextRun        time.Time
	LeaseUntil     time.Time
	Resweep        bool

	Destination  string
	ChainID      uint64
	Nonce        uint64
	OwedMicro    uint64
	ValueMicro   uint64
	ChargeMicro  uint64
	ValueNative  string
	MaxFeeNative string
	RawTx        string
	TxHash       string

	BlockNumber uint64
	GasUsed     uint64
	FeeNative   string
	FeeMicro    uint64
	MarginMicro uint64

	CreatedAt   time.Time
	UpdatedAt   time.Time
	SignedAt    *time.Time
	SubmittedAt *time.Time
	ConfirmedAt *time.Time
}

type PayoutView struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Destination string `json:"destination"`
	Amount      string `json:"amount"`
	NetworkFee  string `json:"network_fee"`
	TxHash      string `json:"tx_hash"`
	BlockNumber uint64 `json:"block_number,omitempty"`
}

func (j *SweepJob) View() PayoutView {
	return PayoutView{
		ID:          j.ID,
		Status:      string(j.State),
		Destination: j.Destination,
		Amount:      FormatUSDC(j.ValueMicro),
		NetworkFee:  FormatUSDC(j.ChargeMicro),
		TxHash:      j.TxHash,
		BlockNumber: j.BlockNumber,
	}
}

type EventPayment struct {
	TxHash      string `json:"tx_hash"`
	From        string `json:"from"`
	Amount      string `json:"amount"`
	BlockNumber uint64 `json:"block_number"`
}

type Event struct {
	ID         string
	Type       string
	MerchantID string
	IntentID   string
	CreatedAt  time.Time
	Payload    []byte
}

type eventBody struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Type    string `json:"type"`
	Created int64  `json:"created"`
	Data    struct {
		PaymentIntent IntentView    `json:"payment_intent"`
		Payment       *EventPayment `json:"payment,omitempty"`
		Payout        *PayoutView   `json:"payout,omitempty"`
	} `json:"data"`
}

func newEvent(typ string, in *Intent, p *Payment, job *SweepJob, now time.Time) Event {
	id := NewID("evt")
	body := eventBody{ID: id, Object: "event", Type: typ, Created: now.Unix()}
	body.Data.PaymentIntent = in.View()
	if p != nil {
		body.Data.Payment = &EventPayment{TxHash: p.TxHash, From: p.From, Amount: FormatUSDC(p.Amount), BlockNumber: p.BlockNumber}
	}
	if job != nil {
		v := job.View()
		body.Data.Payout = &v
	}
	b, _ := json.Marshal(body)
	return Event{ID: id, Type: typ, MerchantID: in.MerchantID, IntentID: in.ID, CreatedAt: now, Payload: b}
}

func NewEvent(typ string, in *Intent, p *Payment, now time.Time) Event {
	return newEvent(typ, in, p, nil, now)
}

func NewPayoutEvent(typ string, in *Intent, job *SweepJob, now time.Time) Event {
	return newEvent(typ, in, nil, job, now)
}

type Delivery struct {
	Event       Event
	Attempts    int
	NextAttempt time.Time
	DeliveredAt *time.Time
	Dead        bool
	LastError   string
}

func NewID(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b)
}

func ParseUSDC(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	whole, frac, _ := strings.Cut(s, ".")
	if whole == "" && frac == "" {
		return 0, errors.New("empty amount")
	}
	if len(frac) > USDCDecimals {
		return 0, fmt.Errorf("at most %d decimal places", USDCDecimals)
	}
	if whole == "" {
		whole = "0"
	}
	frac += strings.Repeat("0", USDCDecimals-len(frac))
	w, err := strconv.ParseUint(whole, 10, 64)
	if err != nil {
		return 0, errors.New("invalid amount")
	}
	f, err := strconv.ParseUint(frac, 10, 64)
	if err != nil {
		return 0, errors.New("invalid amount")
	}
	if w > (math.MaxUint64-f)/unit {
		return 0, errors.New("amount too large")
	}
	return w*unit + f, nil
}

func FormatUSDC(v uint64) string {
	return fmt.Sprintf("%d.%06d", v/unit, v%unit)
}
