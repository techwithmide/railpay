package store

import (
	"context"
	"errors"
	"math/big"
	"time"

	"arcpay/internal/core"
	"arcpay/internal/ledger"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrConflict  = errors.New("concurrent modification")
	ErrDuplicate = errors.New("already exists")
	ErrInvalid   = errors.New("invalid request")
)

type DeliveryResult struct {
	At          time.Time
	Delivered   bool
	Dead        bool
	Err         string
	NextAttempt time.Time
}

type EmailResult struct {
	At          time.Time
	Sent        bool
	Dead        bool
	Err         string
	NextAttempt time.Time
}

type LoginProfile struct{ Provider, Subject, Email, Name string }

type IntentFilter struct {
	Status core.Status
	Limit  int
	After  string
}

type SweepResult struct {
	TxHash      string
	BlockNumber uint64
	GasUsed     uint64
	FeeNative   *big.Int
}

type Deposit struct {
	IntentID    string
	MerchantID  string
	Address     string
	LedgerMicro uint64
	Busy        bool
}

type Stats struct {
	Intents            int    `json:"intents"`
	Pending            int    `json:"pending"`
	Paid               int    `json:"paid"`
	Expired            int    `json:"expired"`
	VolumeMicro        uint64 `json:"volume_micro"`
	FeesMicro          uint64 `json:"fees_micro"`
	PendingPayoutMicro uint64 `json:"pending_payout_micro"`
	SettledMicro       uint64 `json:"settled_micro"`
	NetworkFeesMicro   uint64 `json:"network_fees_micro"`
	PayoutsConfirmed   int    `json:"payouts_confirmed"`
	PayoutsInFlight    int    `json:"payouts_in_flight"`
	PayoutsFailed      int    `json:"payouts_failed"`
}

type Store interface {
	MerchantByID(ctx context.Context, id string) (core.Merchant, error)
	MerchantByAPIKey(ctx context.Context, key string) (core.Merchant, error)
	UpdateMerchant(ctx context.Context, id string, fn func(*core.Merchant) error) (core.Merchant, error)
	LoginUser(ctx context.Context, p LoginProfile, now time.Time) (u core.User, m core.Merchant, created bool, err error)
	SignUpPassword(ctx context.Context, email, passwordHash, name string, now time.Time) (u core.User, m core.Merchant, err error)
	AuthenticatePassword(ctx context.Context, email string) (u core.User, m core.Merchant, passwordHash string, err error)
	UserByID(ctx context.Context, id string) (core.User, error)
	CreateAPIKey(ctx context.Context, merchantID, name string, now time.Time) (plain string, k core.APIKey, err error)
	ListAPIKeys(ctx context.Context, merchantID string) ([]core.APIKey, error)
	RevokeAPIKey(ctx context.Context, merchantID, keyID string, now time.Time) error
	CreateSession(ctx context.Context, userID, merchantID string, ttl time.Duration, now time.Time) (token string, s core.Session, err error)
	SessionByToken(ctx context.Context, token string, now time.Time) (core.Session, error)
	DeleteSession(ctx context.Context, token string) error
	CreateIntent(ctx context.Context, in *core.Intent, idemKey string) (out *core.Intent, created bool, err error)
	GetIntent(ctx context.Context, id string) (*core.Intent, error)
	ListIntents(ctx context.Context, merchantID string, f IntentFilter) (items []*core.Intent, next string, err error)
	IntentPayments(ctx context.Context, intentID string) ([]core.Payment, error)
	WatchedAddresses(ctx context.Context, now time.Time, lateWindow time.Duration) ([]string, error)
	RecordPayment(ctx context.Context, depositAddr string, p core.Payment, now time.Time) (applied bool, err error)
	ExpireDue(ctx context.Context, now time.Time) (int, error)
	LeaseDeliveries(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]core.Delivery, error)
	CompleteDelivery(ctx context.Context, eventID string, res DeliveryResult) error
	ListDeliveries(ctx context.Context, merchantID string, limit int) ([]core.Delivery, error)
	LeaseEmails(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]core.Email, error)
	CompleteEmail(ctx context.Context, id string, res EmailResult) error
	ListEmails(ctx context.Context, merchantID string, limit int) ([]core.Email, error)
	Cursor(ctx context.Context) (block uint64, ok bool, err error)
	SetCursor(ctx context.Context, block uint64) error
	LeaseSweepJobs(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]core.SweepJob, error)
	SaveSweepJob(ctx context.Context, job core.SweepJob, now time.Time) (core.SweepJob, error)
	CompleteSweep(ctx context.Context, jobID string, res SweepResult, now time.Time) (core.SweepJob, error)
	RequeueSweepJob(ctx context.Context, jobID string, now time.Time) error
	GetSweepJob(ctx context.Context, id string) (core.SweepJob, error)
	ListSweepJobs(ctx context.Context, merchantID string, limit int) ([]core.SweepJob, error)
	OwedMicro(ctx context.Context, merchantID, intentID string) (uint64, error)
	Ledger() *ledger.Book
	Deposits(ctx context.Context) ([]Deposit, error)
	MerchantStats(ctx context.Context, merchantID string) (Stats, error)
}
