package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strings"
	"sync"
	"time"

	"arcpay/internal/core"
	"arcpay/internal/ledger"
	"arcpay/internal/store"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxAPIKeysPerMerchant = 20

const schema = `
CREATE TABLE IF NOT EXISTS merchants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    status TEXT NOT NULL,
    fee_bps INTEGER NOT NULL DEFAULT 0,
    settlement_address TEXT NOT NULL DEFAULT '',
    settlement_requested_at TIMESTAMPTZ,
    webhook_url TEXT NOT NULL DEFAULT '',
    webhook_secret TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    password_hash TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (provider, subject)
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    csrf TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS intents (
    id TEXT PRIMARY KEY,
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    amount BIGINT NOT NULL,
    received BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    deposit_address TEXT NOT NULL UNIQUE,
    fee_bps INTEGER NOT NULL DEFAULT 0,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    paid_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS intent_idempotency (
    merchant_id TEXT NOT NULL,
    idem_key TEXT NOT NULL,
    intent_id TEXT NOT NULL REFERENCES intents(id),
    PRIMARY KEY(merchant_id, idem_key)
);

CREATE TABLE IF NOT EXISTS payments (
    tx_hash TEXT NOT NULL,
    log_index BIGINT NOT NULL,
    intent_id TEXT NOT NULL REFERENCES intents(id),
    block_number BIGINT NOT NULL,
    from_address TEXT NOT NULL,
    amount BIGINT NOT NULL,
    PRIMARY KEY(tx_hash, log_index)
);

CREATE TABLE IF NOT EXISTS deliveries (
    event_id TEXT PRIMARY KEY,
    merchant_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    dead BOOLEAN NOT NULL DEFAULT false,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS sweep_jobs (
    id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL REFERENCES intents(id),
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    deposit_address TEXT NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    reason TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    next_run TIMESTAMPTZ NOT NULL,
    lease_until TIMESTAMPTZ,
    resweep BOOLEAN NOT NULL DEFAULT false,
    destination TEXT NOT NULL DEFAULT '',
    chain_id BIGINT NOT NULL DEFAULT 0,
    nonce BIGINT NOT NULL DEFAULT 0,
    owed_micro BIGINT NOT NULL DEFAULT 0,
    value_micro BIGINT NOT NULL DEFAULT 0,
    charge_micro BIGINT NOT NULL DEFAULT 0,
    value_native TEXT NOT NULL DEFAULT '',
    max_fee_native TEXT NOT NULL DEFAULT '',
    raw_tx TEXT NOT NULL DEFAULT '',
    tx_hash TEXT NOT NULL DEFAULT '',
    block_number BIGINT NOT NULL DEFAULT 0,
    gas_used BIGINT NOT NULL DEFAULT 0,
    fee_native TEXT NOT NULL DEFAULT '',
    fee_micro BIGINT NOT NULL DEFAULT 0,
    margin_micro BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    signed_at TIMESTAMPTZ,
    submitted_at TIMESTAMPTZ,
    confirmed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS active_sweep_jobs (
    intent_id TEXT PRIMARY KEY REFERENCES intents(id),
    job_id TEXT NOT NULL REFERENCES sweep_jobs(id)
);

CREATE TABLE IF NOT EXISTS ledger_entries (
    seq BIGINT PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    at TIMESTAMPTZ NOT NULL,
    memo TEXT NOT NULL DEFAULT '',
    meta JSONB NOT NULL DEFAULT '{}',
    lines JSONB NOT NULL,
    prev_hash TEXT NOT NULL DEFAULT '',
    hash TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS system_cursors (
    id TEXT PRIMARY KEY,
    block_number BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS emails (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    to_address TEXT NOT NULL,
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    intent_id TEXT NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt TIMESTAMPTZ NOT NULL,
    sent_at TIMESTAMPTZ,
    dead BOOLEAN NOT NULL DEFAULT false,
    last_error TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS emails_due ON emails (next_attempt) WHERE sent_at IS NULL AND NOT dead;
CREATE INDEX IF NOT EXISTS emails_merchant ON emails (merchant_id, created_at DESC);

ALTER TABLE merchants ADD COLUMN IF NOT EXISTS email_opt_out BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE intents ADD COLUMN IF NOT EXISTS customer_email TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS users_email_lower ON users (lower(email));
`

type Store struct {
	pool          *pgxpool.Pool
	mu            sync.RWMutex
	book          *ledger.Book
	defaultFeeBps uint32
}

var _ store.Store = (*Store)(nil)

func New(ctx context.Context, dsn string, defaultFeeBps uint32) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing postgres DSN: %w", err)
	}
	cfg.MaxConns = 25
	cfg.MinConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("applying schema: %w", err)
	}

	st := &Store{pool: pool, defaultFeeBps: defaultFeeBps}
	if err := st.initLedger(ctx); err != nil {
		return nil, fmt.Errorf("initializing ledger: %w", err)
	}
	return st, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) Ledger() *ledger.Book {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.book
}

func (s *Store) initLedger(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, "SELECT seq, key, kind, at, memo, meta, lines, prev_hash, hash FROM ledger_entries ORDER BY seq ASC")
	if err != nil {
		return err
	}
	defer rows.Close()

	var entries []ledger.Entry
	for rows.Next() {
		var e ledger.Entry
		var metaJSON, linesJSON []byte
		if err := rows.Scan(&e.Seq, &e.Key, &e.Kind, &e.At, &e.Memo, &metaJSON, &linesJSON, &e.PrevHash, &e.Hash); err != nil {
			return err
		}
		if len(metaJSON) > 0 {
			_ = json.Unmarshal(metaJSON, &e.Meta)
		}
		if len(linesJSON) > 0 {
			if err := json.Unmarshal(linesJSON, &e.Lines); err != nil {
				return err
			}
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(entries) == 0 {
		s.book = ledger.NewBook()
		return nil
	}
	book, err := ledger.Restore(entries)
	if err != nil {
		return fmt.Errorf("restoring ledger from postgres: %w", err)
	}
	s.book = book
	return nil
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func prefixOf(key string) string {
	if len(key) > 12 {
		return key[:12]
	}
	return key
}

func randomToken(prefix string, nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

func feeOf(amount uint64, bps uint32) uint64 {
	hi, lo := bits.Mul64(amount, uint64(bps))
	q, _ := bits.Div64(hi, lo, 10_000)
	return q
}

func (s *Store) SeedMerchant(mc core.Merchant, apiKey string) {
	_ = s.SeedMerchantContext(context.Background(), mc, apiKey)
}

func (s *Store) SeedMerchantContext(ctx context.Context, mc core.Merchant, apiKey string) error {
	if mc.Status == "" {
		mc.Status = "active"
	}
	if mc.CreatedAt.IsZero() {
		mc.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO merchants (id, name, email, status, fee_bps, settlement_address, settlement_requested_at, email_opt_out, webhook_url, webhook_secret, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name, email = EXCLUDED.email, status = EXCLUDED.status, fee_bps = EXCLUDED.fee_bps,
			settlement_address = EXCLUDED.settlement_address, settlement_requested_at = EXCLUDED.settlement_requested_at,
			email_opt_out = EXCLUDED.email_opt_out,
			webhook_url = EXCLUDED.webhook_url, webhook_secret = EXCLUDED.webhook_secret
	`, mc.ID, mc.Name, mc.Email, mc.Status, mc.FeeBps, mc.SettlementAddress, nilTime(mc.SettlementRequestedAt), mc.EmailOptOut, mc.WebhookURL, mc.WebhookSecret, mc.CreatedAt)
	if err != nil {
		return err
	}
	if apiKey != "" {
		h := hashSecret(apiKey)
		id := core.NewID("key")
		_, err = s.pool.Exec(ctx, `
			INSERT INTO api_keys (id, merchant_id, name, prefix, hash, created_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (hash) DO NOTHING
		`, id, mc.ID, "seed", prefixOf(apiKey), h, mc.CreatedAt)
		return err
	}
	return nil
}

func nilTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (s *Store) MerchantByID(ctx context.Context, id string) (core.Merchant, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, email, status, fee_bps, settlement_address, settlement_requested_at, email_opt_out, webhook_url, webhook_secret, created_at
		FROM merchants WHERE id = $1
	`, id)
	var m core.Merchant
	var reqAt *time.Time
	if err := row.Scan(&m.ID, &m.Name, &m.Email, &m.Status, &m.FeeBps, &m.SettlementAddress, &reqAt, &m.EmailOptOut, &m.WebhookURL, &m.WebhookSecret, &m.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.Merchant{}, store.ErrNotFound
		}
		return core.Merchant{}, err
	}
	if reqAt != nil {
		m.SettlementRequestedAt = *reqAt
	}
	return m, nil
}

func (s *Store) MerchantByAPIKey(ctx context.Context, key string) (core.Merchant, error) {
	h := hashSecret(key)
	row := s.pool.QueryRow(ctx, `
		SELECT m.id, m.name, m.email, m.status, m.fee_bps, m.settlement_address, m.settlement_requested_at, m.email_opt_out, m.webhook_url, m.webhook_secret, m.created_at, k.id
		FROM api_keys k
		JOIN merchants m ON k.merchant_id = m.id
		WHERE k.hash = $1 AND k.revoked_at IS NULL AND m.status = 'active'
	`, h)
	var m core.Merchant
	var reqAt *time.Time
	var keyID string
	if err := row.Scan(&m.ID, &m.Name, &m.Email, &m.Status, &m.FeeBps, &m.SettlementAddress, &reqAt, &m.EmailOptOut, &m.WebhookURL, &m.WebhookSecret, &m.CreatedAt, &keyID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.Merchant{}, store.ErrNotFound
		}
		return core.Merchant{}, err
	}
	if reqAt != nil {
		m.SettlementRequestedAt = *reqAt
	}
	// Best-effort update of last_used_at
	now := time.Now().UTC()
	_, _ = s.pool.Exec(ctx, "UPDATE api_keys SET last_used_at = $1 WHERE id = $2 AND (last_used_at IS NULL OR last_used_at < $3)", now, keyID, now.Add(-time.Minute))
	return m, nil
}

func (s *Store) UpdateMerchant(ctx context.Context, id string, fn func(*core.Merchant) error) (core.Merchant, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Merchant{}, err
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `
		SELECT id, name, email, status, fee_bps, settlement_address, settlement_requested_at, email_opt_out, webhook_url, webhook_secret, created_at
		FROM merchants WHERE id = $1 FOR UPDATE
	`, id)
	var m core.Merchant
	var reqAt *time.Time
	if err := row.Scan(&m.ID, &m.Name, &m.Email, &m.Status, &m.FeeBps, &m.SettlementAddress, &reqAt, &m.EmailOptOut, &m.WebhookURL, &m.WebhookSecret, &m.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.Merchant{}, store.ErrNotFound
		}
		return core.Merchant{}, err
	}
	if reqAt != nil {
		m.SettlementRequestedAt = *reqAt
	}
	c := m
	if err := fn(&c); err != nil {
		return core.Merchant{}, err
	}
	c.ID, c.CreatedAt = m.ID, m.CreatedAt
	_, err = tx.Exec(ctx, `
		UPDATE merchants SET
			name = $1, email = $2, status = $3, fee_bps = $4,
			settlement_address = $5, settlement_requested_at = $6,
			email_opt_out = $7, webhook_url = $8, webhook_secret = $9
		WHERE id = $10
	`, c.Name, c.Email, c.Status, c.FeeBps, c.SettlementAddress, nilTime(c.SettlementRequestedAt), c.EmailOptOut, c.WebhookURL, c.WebhookSecret, c.ID)
	if err != nil {
		return core.Merchant{}, err
	}
	return c, tx.Commit(ctx)
}

func (s *Store) LoginUser(ctx context.Context, p store.LoginProfile, now time.Time) (core.User, core.Merchant, bool, error) {
	if p.Provider == "" || p.Subject == "" {
		return core.User{}, core.Merchant{}, false, fmt.Errorf("%w: provider and subject are required", store.ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.User{}, core.Merchant{}, false, err
	}
	defer tx.Rollback(ctx)

	var u core.User
	row := tx.QueryRow(ctx, "SELECT id, provider, subject, email, name, merchant_id, password_hash, created_at FROM users WHERE provider = $1 AND subject = $2", p.Provider, p.Subject)
	if err := row.Scan(&u.ID, &u.Provider, &u.Subject, &u.Email, &u.Name, &u.MerchantID, &u.PasswordHash, &u.CreatedAt); err == nil {
		var m core.Merchant
		var reqAt *time.Time
		mRow := tx.QueryRow(ctx, "SELECT id, name, email, status, fee_bps, settlement_address, settlement_requested_at, email_opt_out, webhook_url, webhook_secret, created_at FROM merchants WHERE id = $1", u.MerchantID)
		if err := mRow.Scan(&m.ID, &m.Name, &m.Email, &m.Status, &m.FeeBps, &m.SettlementAddress, &reqAt, &m.EmailOptOut, &m.WebhookURL, &m.WebhookSecret, &m.CreatedAt); err != nil {
			return core.User{}, core.Merchant{}, false, err
		}
		if reqAt != nil {
			m.SettlementRequestedAt = *reqAt
		}
		if m.Status != "active" {
			return core.User{}, core.Merchant{}, false, fmt.Errorf("%w: account suspended", store.ErrNotFound)
		}
		return u, m, false, tx.Commit(ctx)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return core.User{}, core.Merchant{}, false, err
	}

	name := strings.TrimSpace(p.Name)
	if name == "" {
		name, _, _ = strings.Cut(p.Email, "@")
	}
	if name == "" {
		name = "My business"
	}
	mc := core.Merchant{
		ID: core.NewID("mch"), Name: name, Email: p.Email, Status: "active", FeeBps: s.defaultFeeBps,
		WebhookSecret: randomToken("whsec_", 24), CreatedAt: now.UTC(),
	}
	u = core.User{ID: core.NewID("usr"), Provider: p.Provider, Subject: p.Subject, Email: p.Email, Name: p.Name, MerchantID: mc.ID, CreatedAt: now.UTC()}

	_, err = tx.Exec(ctx, `
		INSERT INTO merchants (id, name, email, status, fee_bps, settlement_address, settlement_requested_at, email_opt_out, webhook_url, webhook_secret, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, mc.ID, mc.Name, mc.Email, mc.Status, mc.FeeBps, mc.SettlementAddress, nilTime(mc.SettlementRequestedAt), mc.EmailOptOut, mc.WebhookURL, mc.WebhookSecret, mc.CreatedAt)
	if err != nil {
		return core.User{}, core.Merchant{}, false, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, provider, subject, email, name, merchant_id, password_hash, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, u.ID, u.Provider, u.Subject, u.Email, u.Name, u.MerchantID, u.PasswordHash, u.CreatedAt)
	if err != nil {
		return core.User{}, core.Merchant{}, false, err
	}
	return u, mc, true, tx.Commit(ctx)
}

func (s *Store) UserByID(ctx context.Context, id string) (core.User, error) {
	row := s.pool.QueryRow(ctx, "SELECT id, provider, subject, email, name, merchant_id, password_hash, created_at FROM users WHERE id = $1", id)
	var u core.User
	if err := row.Scan(&u.ID, &u.Provider, &u.Subject, &u.Email, &u.Name, &u.MerchantID, &u.PasswordHash, &u.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.User{}, store.ErrNotFound
		}
		return core.User{}, err
	}
	return u, nil
}

func (s *Store) SignUpPassword(ctx context.Context, email, passwordHash, name string, now time.Time) (core.User, core.Merchant, error) {
	cleanEmail, err := core.ValidEmail(email)
	if err != nil {
		return core.User{}, core.Merchant{}, fmt.Errorf("%w: invalid email address", store.ErrInvalid)
	}
	email = cleanEmail
	if passwordHash == "" {
		return core.User{}, core.Merchant{}, fmt.Errorf("%w: password required", store.ErrInvalid)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.User{}, core.Merchant{}, err
	}
	defer tx.Rollback(ctx)

	var existingID string
	err = tx.QueryRow(ctx, "SELECT id FROM users WHERE lower(email) = lower($1)", email).Scan(&existingID)
	if err == nil {
		return core.User{}, core.Merchant{}, fmt.Errorf("%w: an account with this email already exists", store.ErrDuplicate)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return core.User{}, core.Merchant{}, err
	}

	name = strings.TrimSpace(name)
	if name == "" {
		name, _, _ = strings.Cut(email, "@")
	}
	if name == "" {
		name = "My business"
	}

	mc := core.Merchant{
		ID:            core.NewID("mch"),
		Name:          name,
		Email:         email,
		Status:        "active",
		FeeBps:        s.defaultFeeBps,
		WebhookSecret: randomToken("whsec_", 24),
		CreatedAt:     now.UTC(),
	}
	u := core.User{
		ID:           core.NewID("usr"),
		Provider:     "password",
		Subject:      strings.ToLower(email),
		Email:        email,
		Name:         name,
		MerchantID:   mc.ID,
		PasswordHash: passwordHash,
		CreatedAt:    now.UTC(),
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO merchants (id, name, email, status, fee_bps, settlement_address, settlement_requested_at, email_opt_out, webhook_url, webhook_secret, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, mc.ID, mc.Name, mc.Email, mc.Status, mc.FeeBps, mc.SettlementAddress, nilTime(mc.SettlementRequestedAt), mc.EmailOptOut, mc.WebhookURL, mc.WebhookSecret, mc.CreatedAt)
	if err != nil {
		return core.User{}, core.Merchant{}, err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, provider, subject, email, name, merchant_id, password_hash, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, u.ID, u.Provider, u.Subject, u.Email, u.Name, u.MerchantID, u.PasswordHash, u.CreatedAt)
	if err != nil {
		return core.User{}, core.Merchant{}, err
	}

	plainKey := randomToken("sk_live_", 32)
	k := core.APIKey{
		ID:         core.NewID("key"),
		MerchantID: mc.ID,
		Name:       "Default Key",
		Prefix:     plainKey[:12],
		Hash:       hashSecret(plainKey),
		CreatedAt:  now.UTC(),
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO api_keys (id, merchant_id, name, prefix, hash, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, k.ID, k.MerchantID, k.Name, k.Prefix, k.Hash, k.CreatedAt)
	if err != nil {
		return core.User{}, core.Merchant{}, err
	}

	return u, mc, tx.Commit(ctx)
}

func (s *Store) AuthenticatePassword(ctx context.Context, email string) (core.User, core.Merchant, string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return core.User{}, core.Merchant{}, "", fmt.Errorf("%w: email required", store.ErrInvalid)
	}

	var u core.User
	row := s.pool.QueryRow(ctx, `
		SELECT id, provider, subject, email, name, merchant_id, password_hash, created_at
		FROM users
		WHERE lower(email) = lower($1) AND password_hash != ''
		ORDER BY created_at DESC LIMIT 1
	`, email)
	if err := row.Scan(&u.ID, &u.Provider, &u.Subject, &u.Email, &u.Name, &u.MerchantID, &u.PasswordHash, &u.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.User{}, core.Merchant{}, "", store.ErrNotFound
		}
		return core.User{}, core.Merchant{}, "", err
	}

	m, err := s.MerchantByID(ctx, u.MerchantID)
	if err != nil {
		return core.User{}, core.Merchant{}, "", err
	}
	if m.Status != "active" {
		return core.User{}, core.Merchant{}, "", fmt.Errorf("%w: account suspended", store.ErrNotFound)
	}

	return u, m, u.PasswordHash, nil
}

func (s *Store) CreateAPIKey(ctx context.Context, merchantID, name string, now time.Time) (string, core.APIKey, error) {
	var count int
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM api_keys WHERE merchant_id = $1 AND revoked_at IS NULL", merchantID).Scan(&count)
	if err != nil {
		return "", core.APIKey{}, err
	}
	if count >= maxAPIKeysPerMerchant {
		return "", core.APIKey{}, fmt.Errorf("%w: at most %d active API keys", store.ErrInvalid, maxAPIKeysPerMerchant)
	}
	name = strings.TrimSpace(name)
	if len(name) > 60 {
		return "", core.APIKey{}, fmt.Errorf("%w: key name too long", store.ErrInvalid)
	}
	plain := randomToken("sk_live_", 32)
	k := core.APIKey{
		ID: core.NewID("key"), MerchantID: merchantID, Name: name, Prefix: prefixOf(plain),
		Hash: hashSecret(plain), CreatedAt: now.UTC(),
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO api_keys (id, merchant_id, name, prefix, hash, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, k.ID, k.MerchantID, k.Name, k.Prefix, k.Hash, k.CreatedAt)
	if err != nil {
		return "", core.APIKey{}, err
	}
	return plain, k, nil
}

func (s *Store) ListAPIKeys(ctx context.Context, merchantID string) ([]core.APIKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, merchant_id, name, prefix, hash, created_at, last_used_at, revoked_at
		FROM api_keys WHERE merchant_id = $1 ORDER BY created_at DESC, id DESC
	`, merchantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.APIKey
	for rows.Next() {
		var k core.APIKey
		if err := rows.Scan(&k.ID, &k.MerchantID, &k.Name, &k.Prefix, &k.Hash, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAPIKey(ctx context.Context, merchantID, keyID string, now time.Time) error {
	t := now.UTC()
	cmd, err := s.pool.Exec(ctx, "UPDATE api_keys SET revoked_at = $1 WHERE id = $2 AND merchant_id = $3 AND revoked_at IS NULL", t, keyID, merchantID)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, userID, merchantID string, ttl time.Duration, now time.Time) (string, core.Session, error) {
	token := randomToken("ses_", 32)
	sess := core.Session{
		ID: hashSecret(token), UserID: userID, MerchantID: merchantID, CSRF: randomToken("", 24),
		CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(ttl),
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, merchant_id, csrf, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, sess.ID, sess.UserID, sess.MerchantID, sess.CSRF, sess.CreatedAt, sess.ExpiresAt)
	if err != nil {
		return "", core.Session{}, err
	}
	// Opportunistic session cleanup
	go func() {
		_, _ = s.pool.Exec(context.Background(), "DELETE FROM sessions WHERE expires_at < $1", now.UTC())
	}()
	return token, sess, nil
}

func (s *Store) SessionByToken(ctx context.Context, token string, now time.Time) (core.Session, error) {
	h := hashSecret(token)
	row := s.pool.QueryRow(ctx, `
		SELECT s.id, s.user_id, s.merchant_id, s.csrf, s.created_at, s.expires_at
		FROM sessions s
		JOIN merchants m ON s.merchant_id = m.id
		WHERE s.id = $1 AND s.expires_at > $2 AND m.status = 'active'
	`, h, now.UTC())
	var sess core.Session
	if err := row.Scan(&sess.ID, &sess.UserID, &sess.MerchantID, &sess.CSRF, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.Session{}, store.ErrNotFound
		}
		return core.Session{}, err
	}
	return sess, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM sessions WHERE id = $1", hashSecret(token))
	return err
}

func (s *Store) CreateIntent(ctx context.Context, in *core.Intent, idemKey string) (*core.Intent, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)

	if idemKey != "" {
		var existingID string
		err := tx.QueryRow(ctx, "SELECT intent_id FROM intent_idempotency WHERE merchant_id = $1 AND idem_key = $2", in.MerchantID, idemKey).Scan(&existingID)
		if err == nil {
			var existing core.Intent
			var metaJSON []byte
			row := tx.QueryRow(ctx, `
				SELECT id, merchant_id, amount, received, status, deposit_address, fee_bps, customer_email, metadata, created_at, expires_at, paid_at
				FROM intents WHERE id = $1
			`, existingID)
			if err := row.Scan(&existing.ID, &existing.MerchantID, &existing.Amount, &existing.Received, &existing.Status,
				&existing.DepositAddress, &existing.FeeBps, &existing.CustomerEmail, &metaJSON, &existing.CreatedAt, &existing.ExpiresAt, &existing.PaidAt); err == nil {
				if len(metaJSON) > 0 {
					_ = json.Unmarshal(metaJSON, &existing.Metadata)
				}
				return &existing, false, tx.Commit(ctx)
			}
		}
	}

	metaJSON, _ := json.Marshal(in.Metadata)
	if in.Metadata == nil {
		metaJSON = []byte("{}")
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO intents (id, merchant_id, amount, received, status, deposit_address, fee_bps, customer_email, metadata, created_at, expires_at, paid_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, in.ID, in.MerchantID, in.Amount, in.Received, in.Status, in.DepositAddress, in.FeeBps, in.CustomerEmail, metaJSON, in.CreatedAt, in.ExpiresAt, in.PaidAt)
	if err != nil {
		return nil, false, err
	}
	if idemKey != "" {
		_, err = tx.Exec(ctx, "INSERT INTO intent_idempotency (merchant_id, idem_key, intent_id) VALUES ($1, $2, $3)", in.MerchantID, idemKey, in.ID)
		if err != nil {
			return nil, false, err
		}
	}
	return in.Clone(), true, tx.Commit(ctx)
}

func (s *Store) GetIntent(ctx context.Context, id string) (*core.Intent, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, merchant_id, amount, received, status, deposit_address, fee_bps, customer_email, metadata, created_at, expires_at, paid_at
		FROM intents WHERE id = $1
	`, id)
	var in core.Intent
	var metaJSON []byte
	if err := row.Scan(&in.ID, &in.MerchantID, &in.Amount, &in.Received, &in.Status,
		&in.DepositAddress, &in.FeeBps, &in.CustomerEmail, &metaJSON, &in.CreatedAt, &in.ExpiresAt, &in.PaidAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if len(metaJSON) > 0 {
		_ = json.Unmarshal(metaJSON, &in.Metadata)
	}
	return &in, nil
}

func (s *Store) ListIntents(ctx context.Context, merchantID string, f store.IntentFilter) ([]*core.Intent, string, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}

	query := `
		SELECT id, merchant_id, amount, received, status, deposit_address, fee_bps, customer_email, metadata, created_at, expires_at, paid_at
		FROM intents WHERE merchant_id = $1
	`
	args := []any{merchantID}
	if f.Status != "" {
		args = append(args, f.Status)
		query += fmt.Sprintf(" AND status = $%d", len(args))
	}
	query += " ORDER BY created_at DESC, id DESC"
	args = append(args, limit+1)
	query += fmt.Sprintf(" LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var all []*core.Intent
	for rows.Next() {
		var in core.Intent
		var metaJSON []byte
		if err := rows.Scan(&in.ID, &in.MerchantID, &in.Amount, &in.Received, &in.Status,
			&in.DepositAddress, &in.FeeBps, &in.CustomerEmail, &metaJSON, &in.CreatedAt, &in.ExpiresAt, &in.PaidAt); err != nil {
			return nil, "", err
		}
		if len(metaJSON) > 0 {
			_ = json.Unmarshal(metaJSON, &in.Metadata)
		}
		all = append(all, &in)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}

	next := ""
	if len(all) > limit {
		next = all[limit-1].ID
		all = all[:limit]
	}
	return all, next, nil
}

func (s *Store) IntentPayments(ctx context.Context, intentID string) ([]core.Payment, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT tx_hash, log_index, intent_id, block_number, from_address, amount
		FROM payments WHERE intent_id = $1 ORDER BY block_number ASC, log_index ASC
	`, intentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.Payment
	for rows.Next() {
		var p core.Payment
		if err := rows.Scan(&p.TxHash, &p.LogIndex, &p.IntentID, &p.BlockNumber, &p.From, &p.Amount); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) WatchedAddresses(ctx context.Context, now time.Time, late time.Duration) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT deposit_address FROM intents
		WHERE (status = $1 AND expires_at + $2 > $3)
		   OR (status = $4 AND paid_at IS NOT NULL AND paid_at + $2 > $3)
	`, core.StatusPending, late, now.UTC(), core.StatusPaid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	sort.Strings(out)
	return out, rows.Err()
}

func (s *Store) RecordPayment(ctx context.Context, addr string, p core.Payment, now time.Time) (bool, error) {
	if p.Amount == 0 {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	var in core.Intent
	var metaJSON []byte
	row := tx.QueryRow(ctx, `
		SELECT id, merchant_id, amount, received, status, deposit_address, fee_bps, customer_email, metadata, created_at, expires_at, paid_at
		FROM intents WHERE deposit_address = $1 FOR UPDATE
	`, addr)
	if err := row.Scan(&in.ID, &in.MerchantID, &in.Amount, &in.Received, &in.Status,
		&in.DepositAddress, &in.FeeBps, &in.CustomerEmail, &metaJSON, &in.CreatedAt, &in.ExpiresAt, &in.PaidAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, store.ErrNotFound
		}
		return false, err
	}

	key := fmt.Sprintf("payment:%s:%d", strings.ToLower(p.TxHash), p.LogIndex)
	if _, dup := s.book.Get(key); dup {
		return false, nil
	}

	bps := in.FeeBps
	if bps > 10_000 {
		bps = 10_000
	}
	fee := feeOf(p.Amount, bps)
	lines := []ledger.Line{
		{Account: ledger.DepositAccount(in.ID), Debit: p.Amount},
		{Account: ledger.MerchantAccount(in.MerchantID, in.ID), Credit: p.Amount - fee},
	}
	if fee > 0 {
		lines = append(lines, ledger.Line{Account: ledger.RevenueFees, Credit: fee})
	}
	if lines[1].Credit == 0 {
		lines = append(lines[:1], lines[2:]...)
	}

	postEntry, _, err := s.book.Post(ledger.Entry{
		Key: key, Kind: "payment", At: now, Lines: lines,
		Meta: map[string]string{
			"intent": in.ID, "merchant": in.MerchantID, "tx": strings.ToLower(p.TxHash),
			"from": p.From, "block": fmt.Sprint(p.BlockNumber),
		},
	})
	if err != nil {
		return false, fmt.Errorf("posting payment to ledger: %w", err)
	}

	// Persist ledger entry
	linesB, _ := json.Marshal(postEntry.Lines)
	metaB, _ := json.Marshal(postEntry.Meta)
	_, err = tx.Exec(ctx, `
		INSERT INTO ledger_entries (seq, key, kind, at, memo, meta, lines, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, postEntry.Seq, postEntry.Key, postEntry.Kind, postEntry.At, postEntry.Memo, metaB, linesB, postEntry.PrevHash, postEntry.Hash)
	if err != nil {
		return false, err
	}

	// Persist payment
	_, err = tx.Exec(ctx, `
		INSERT INTO payments (tx_hash, log_index, intent_id, block_number, from_address, amount)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, p.TxHash, p.LogIndex, in.ID, p.BlockNumber, p.From, p.Amount)
	if err != nil {
		return false, err
	}

	p.IntentID = in.ID
	if typ := in.ApplyPayment(p.Amount, now); typ != "" {
		ev := core.NewEvent(typ, &in, &p, now)
		_, err = tx.Exec(ctx, `
			INSERT INTO deliveries (event_id, merchant_id, intent_id, event_type, payload, next_attempt, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, ev.ID, ev.MerchantID, ev.IntentID, ev.Type, ev.Payload, now.UTC(), now.UTC())
		if err != nil {
			return false, err
		}

		var mc core.Merchant
		var reqAt *time.Time
		mRow := tx.QueryRow(ctx, "SELECT id, name, email, status, fee_bps, settlement_address, settlement_requested_at, email_opt_out, webhook_url, webhook_secret, created_at FROM merchants WHERE id = $1", in.MerchantID)
		if err := mRow.Scan(&mc.ID, &mc.Name, &mc.Email, &mc.Status, &mc.FeeBps, &mc.SettlementAddress, &reqAt, &mc.EmailOptOut, &mc.WebhookURL, &mc.WebhookSecret, &mc.CreatedAt); err == nil {
			for _, em := range core.EmailsFor(ev, mc, &in, &p, nil, now) {
				dataB, _ := json.Marshal(em.Data)
				_, err = tx.Exec(ctx, `
					INSERT INTO emails (id, key, kind, to_address, merchant_id, intent_id, data, created_at, next_attempt)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
					ON CONFLICT (key) DO NOTHING
				`, em.ID, em.Key, em.Kind, em.To, em.MerchantID, em.IntentID, dataB, now.UTC(), now.UTC())
				if err != nil {
					return false, err
				}
			}
		}
	}

	// Update intent
	_, err = tx.Exec(ctx, `
		UPDATE intents SET received = $1, status = $2, paid_at = $3 WHERE id = $4
	`, in.Received, in.Status, in.PaidAt, in.ID)
	if err != nil {
		return false, err
	}

	// Ensure sweep job
	var activeJobID string
	err = tx.QueryRow(ctx, "SELECT job_id FROM active_sweep_jobs WHERE intent_id = $1", in.ID).Scan(&activeJobID)
	if errors.Is(err, pgx.ErrNoRows) {
		job := core.SweepJob{
			ID: core.NewID("swp"), IntentID: in.ID, MerchantID: in.MerchantID, DepositAddress: in.DepositAddress,
			State: core.SweepQueued, NextRun: now.UTC(), CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO sweep_jobs (id, intent_id, merchant_id, deposit_address, state, next_run, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, job.ID, job.IntentID, job.MerchantID, job.DepositAddress, job.State, job.NextRun, job.CreatedAt, job.UpdatedAt)
		if err != nil {
			return false, err
		}
		_, err = tx.Exec(ctx, "INSERT INTO active_sweep_jobs (intent_id, job_id) VALUES ($1, $2)", in.ID, job.ID)
		if err != nil {
			return false, err
		}
	} else if err == nil {
		_, _ = tx.Exec(ctx, `
			UPDATE sweep_jobs SET next_run = $1, version = version + 1
			WHERE id = $2 AND state = $3
		`, now.UTC(), activeJobID, core.SweepQueued)
	}

	return true, tx.Commit(ctx)
}

func (s *Store) ExpireDue(ctx context.Context, now time.Time) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT id, merchant_id, amount, received, status, deposit_address, fee_bps, customer_email, metadata, created_at, expires_at, paid_at
		FROM intents WHERE status = $1 AND expires_at < $2 FOR UPDATE
	`, core.StatusPending, now.UTC())
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var expired []*core.Intent
	for rows.Next() {
		var in core.Intent
		var metaJSON []byte
		if err := rows.Scan(&in.ID, &in.MerchantID, &in.Amount, &in.Received, &in.Status,
			&in.DepositAddress, &in.FeeBps, &in.CustomerEmail, &metaJSON, &in.CreatedAt, &in.ExpiresAt, &in.PaidAt); err != nil {
			return 0, err
		}
		if len(metaJSON) > 0 {
			_ = json.Unmarshal(metaJSON, &in.Metadata)
		}
		expired = append(expired, &in)
	}
	rows.Close()

	n := 0
	for _, in := range expired {
		if in.ExpireIfDue(now) {
			_, err = tx.Exec(ctx, "UPDATE intents SET status = $1 WHERE id = $2", in.Status, in.ID)
			if err != nil {
				return 0, err
			}
			ev := core.NewEvent(core.EventExpired, in, nil, now)
			_, err = tx.Exec(ctx, `
				INSERT INTO deliveries (event_id, merchant_id, intent_id, event_type, payload, next_attempt, created_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7)
			`, ev.ID, ev.MerchantID, ev.IntentID, ev.Type, ev.Payload, now.UTC(), now.UTC())
			if err != nil {
				return 0, err
			}
			n++
		}
	}
	return n, tx.Commit(ctx)
}

func (s *Store) LeaseDeliveries(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]core.Delivery, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT event_id, merchant_id, intent_id, event_type, payload, attempts, next_attempt, delivered_at, dead, last_error, created_at
		FROM deliveries
		WHERE delivered_at IS NULL AND dead = false AND next_attempt <= $1
		ORDER BY next_attempt ASC, event_id ASC
		LIMIT $2 FOR UPDATE SKIP LOCKED
	`, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var due []core.Delivery
	var ids []string
	for rows.Next() {
		var d core.Delivery
		var pl []byte
		if err := rows.Scan(&d.Event.ID, &d.Event.MerchantID, &d.Event.IntentID, &d.Event.Type, &pl,
			&d.Attempts, &d.NextAttempt, &d.DeliveredAt, &d.Dead, &d.LastError, &d.Event.CreatedAt); err != nil {
			return nil, err
		}
		d.Event.Payload = pl
		due = append(due, d)
		ids = append(ids, d.Event.ID)
	}
	rows.Close()

	if len(ids) > 0 {
		_, err = tx.Exec(ctx, `
			UPDATE deliveries SET next_attempt = $1 WHERE event_id = ANY($2)
		`, now.UTC().Add(lease), ids)
		if err != nil {
			return nil, err
		}
	}
	return due, tx.Commit(ctx)
}

func (s *Store) CompleteDelivery(ctx context.Context, eventID string, res store.DeliveryResult) error {
	switch {
	case res.Delivered:
		_, err := s.pool.Exec(ctx, `
			UPDATE deliveries SET attempts = attempts + 1, delivered_at = $1, last_error = '' WHERE event_id = $2
		`, res.At.UTC(), eventID)
		return err
	case res.Dead:
		_, err := s.pool.Exec(ctx, `
			UPDATE deliveries SET attempts = attempts + 1, dead = true, last_error = $1 WHERE event_id = $2
		`, res.Err, eventID)
		return err
	default:
		_, err := s.pool.Exec(ctx, `
			UPDATE deliveries SET attempts = attempts + 1, next_attempt = $1, last_error = $2 WHERE event_id = $3
		`, res.NextAttempt.UTC(), res.Err, eventID)
		return err
	}
}

func (s *Store) ListDeliveries(ctx context.Context, merchantID string, limit int) ([]core.Delivery, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT event_id, merchant_id, intent_id, event_type, payload, attempts, next_attempt, delivered_at, dead, last_error, created_at
		FROM deliveries WHERE merchant_id = $1 ORDER BY created_at DESC, event_id DESC LIMIT $2
	`, merchantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.Delivery
	for rows.Next() {
		var d core.Delivery
		var pl []byte
		if err := rows.Scan(&d.Event.ID, &d.Event.MerchantID, &d.Event.IntentID, &d.Event.Type, &pl,
			&d.Attempts, &d.NextAttempt, &d.DeliveredAt, &d.Dead, &d.LastError, &d.Event.CreatedAt); err != nil {
			return nil, err
		}
		d.Event.Payload = pl
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) LeaseEmails(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]core.Email, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT id, key, kind, to_address, merchant_id, intent_id, data, created_at, attempts, next_attempt, sent_at, dead, last_error
		FROM emails
		WHERE sent_at IS NULL AND NOT dead AND next_attempt <= $1
		ORDER BY next_attempt ASC, id ASC
		LIMIT $2 FOR UPDATE SKIP LOCKED
	`, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var due []core.Email
	var ids []string
	for rows.Next() {
		var e core.Email
		var dataB []byte
		if err := rows.Scan(&e.ID, &e.Key, &e.Kind, &e.To, &e.MerchantID, &e.IntentID, &dataB,
			&e.CreatedAt, &e.Attempts, &e.NextAttempt, &e.SentAt, &e.Dead, &e.LastError); err != nil {
			return nil, err
		}
		if len(dataB) > 0 {
			_ = json.Unmarshal(dataB, &e.Data)
		}
		due = append(due, e)
		ids = append(ids, e.ID)
	}
	rows.Close()

	if len(ids) > 0 {
		_, err = tx.Exec(ctx, `
			UPDATE emails SET next_attempt = $1 WHERE id = ANY($2)
		`, now.UTC().Add(lease), ids)
		if err != nil {
			return nil, err
		}
	}
	return due, tx.Commit(ctx)
}

func (s *Store) CompleteEmail(ctx context.Context, id string, res store.EmailResult) error {
	if res.Sent {
		_, err := s.pool.Exec(ctx, `
			UPDATE emails SET attempts = attempts + 1, sent_at = $1, last_error = '' WHERE id = $2
		`, res.At.UTC(), id)
		return err
	}
	if res.Dead {
		_, err := s.pool.Exec(ctx, `
			UPDATE emails SET attempts = attempts + 1, dead = true, last_error = $1 WHERE id = $2
		`, res.Err, id)
		return err
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE emails SET attempts = attempts + 1, next_attempt = $1, last_error = $2 WHERE id = $3
	`, res.NextAttempt.UTC(), res.Err, id)
	return err
}

func (s *Store) ListEmails(ctx context.Context, merchantID string, limit int) ([]core.Email, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, key, kind, to_address, merchant_id, intent_id, data, created_at, attempts, next_attempt, sent_at, dead, last_error
		FROM emails WHERE merchant_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2
	`, merchantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.Email
	for rows.Next() {
		var e core.Email
		var dataB []byte
		if err := rows.Scan(&e.ID, &e.Key, &e.Kind, &e.To, &e.MerchantID, &e.IntentID, &dataB,
			&e.CreatedAt, &e.Attempts, &e.NextAttempt, &e.SentAt, &e.Dead, &e.LastError); err != nil {
			return nil, err
		}
		if len(dataB) > 0 {
			_ = json.Unmarshal(dataB, &e.Data)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Cursor(ctx context.Context) (uint64, bool, error) {
	var blk uint64
	err := s.pool.QueryRow(ctx, "SELECT block_number FROM system_cursors WHERE id = 'watcher'").Scan(&blk)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return blk, true, nil
}

func (s *Store) SetCursor(ctx context.Context, block uint64) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO system_cursors (id, block_number) VALUES ('watcher', $1)
		ON CONFLICT (id) DO UPDATE SET block_number = EXCLUDED.block_number
	`, block)
	return err
}

func (s *Store) LeaseSweepJobs(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]core.SweepJob, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT id, intent_id, merchant_id, deposit_address, state, version, attempts, reason, last_error,
		       next_run, lease_until, resweep, destination, chain_id, nonce, owed_micro, value_micro, charge_micro,
		       value_native, max_fee_native, raw_tx, tx_hash, block_number, gas_used, fee_native, fee_micro, margin_micro,
		       created_at, updated_at, signed_at, submitted_at, confirmed_at
		FROM sweep_jobs
		WHERE state IN ('queued', 'signed', 'submitted')
		  AND next_run <= $1
		  AND (lease_until IS NULL OR lease_until <= $1)
		ORDER BY next_run ASC, id ASC
		LIMIT $2 FOR UPDATE SKIP LOCKED
	`, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var due []core.SweepJob
	var ids []string
	for rows.Next() {
		var j core.SweepJob
		var leaseUntil *time.Time
		if err := rows.Scan(&j.ID, &j.IntentID, &j.MerchantID, &j.DepositAddress, &j.State, &j.Version, &j.Attempts,
			&j.Reason, &j.LastError, &j.NextRun, &leaseUntil, &j.Resweep, &j.Destination, &j.ChainID, &j.Nonce,
			&j.OwedMicro, &j.ValueMicro, &j.ChargeMicro, &j.ValueNative, &j.MaxFeeNative, &j.RawTx, &j.TxHash,
			&j.BlockNumber, &j.GasUsed, &j.FeeNative, &j.FeeMicro, &j.MarginMicro,
			&j.CreatedAt, &j.UpdatedAt, &j.SignedAt, &j.SubmittedAt, &j.ConfirmedAt); err != nil {
			return nil, err
		}
		if leaseUntil != nil {
			j.LeaseUntil = *leaseUntil
		}
		due = append(due, j)
		ids = append(ids, j.ID)
	}
	rows.Close()

	if len(ids) > 0 {
		leaseUntil := now.UTC().Add(lease)
		_, err = tx.Exec(ctx, `
			UPDATE sweep_jobs SET lease_until = $1, version = version + 1 WHERE id = ANY($2)
		`, leaseUntil, ids)
		if err != nil {
			return nil, err
		}
		for i := range due {
			due[i].LeaseUntil = leaseUntil
			due[i].Version++
		}
	}
	return due, tx.Commit(ctx)
}

func (s *Store) SaveSweepJob(ctx context.Context, job core.SweepJob, now time.Time) (core.SweepJob, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.SweepJob{}, err
	}
	defer tx.Rollback(ctx)

	var curState core.SweepState
	var curVersion uint64
	var curResweep bool
	row := tx.QueryRow(ctx, "SELECT state, version, resweep FROM sweep_jobs WHERE id = $1 FOR UPDATE", job.ID)
	if err := row.Scan(&curState, &curVersion, &curResweep); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.SweepJob{}, store.ErrNotFound
		}
		return core.SweepJob{}, err
	}
	if curVersion != job.Version {
		return core.SweepJob{}, store.ErrConflict
	}
	if curState == core.SweepConfirmed || job.State == core.SweepConfirmed {
		return core.SweepJob{}, fmt.Errorf("%w: confirmation goes through CompleteSweep", store.ErrInvalid)
	}

	wasFailed := curState == core.SweepFailed
	job.Resweep = job.Resweep || curResweep
	job.UpdatedAt = now.UTC()
	job.Version = curVersion + 1

	_, err = tx.Exec(ctx, `
		UPDATE sweep_jobs SET
			state = $1, version = $2, attempts = $3, reason = $4, last_error = $5,
			next_run = $6, lease_until = $7, resweep = $8, destination = $9, chain_id = $10,
			nonce = $11, owed_micro = $12, value_micro = $13, charge_micro = $14,
			value_native = $15, max_fee_native = $16, raw_tx = $17, tx_hash = $18,
			block_number = $19, gas_used = $20, fee_native = $21, fee_micro = $22, margin_micro = $23,
			updated_at = $24, signed_at = $25, submitted_at = $26, confirmed_at = $27
		WHERE id = $28
	`, job.State, job.Version, job.Attempts, job.Reason, job.LastError,
		job.NextRun, nilTime(job.LeaseUntil), job.Resweep, job.Destination, job.ChainID,
		job.Nonce, job.OwedMicro, job.ValueMicro, job.ChargeMicro,
		job.ValueNative, job.MaxFeeNative, job.RawTx, job.TxHash,
		job.BlockNumber, job.GasUsed, job.FeeNative, job.FeeMicro, job.MarginMicro,
		job.UpdatedAt, job.SignedAt, job.SubmittedAt, job.ConfirmedAt, job.ID)
	if err != nil {
		return core.SweepJob{}, err
	}

	if job.State == core.SweepFailed && !wasFailed {
		var in core.Intent
		var metaJSON []byte
		row := tx.QueryRow(ctx, "SELECT id, merchant_id, amount, received, status, deposit_address, fee_bps, customer_email, metadata, created_at, expires_at, paid_at FROM intents WHERE id = $1", job.IntentID)
		if err := row.Scan(&in.ID, &in.MerchantID, &in.Amount, &in.Received, &in.Status, &in.DepositAddress, &in.FeeBps, &in.CustomerEmail, &metaJSON, &in.CreatedAt, &in.ExpiresAt, &in.PaidAt); err == nil {
			ev := core.NewPayoutEvent(core.EventPayoutFailed, &in, &job, now)
			_, _ = tx.Exec(ctx, `
				INSERT INTO deliveries (event_id, merchant_id, intent_id, event_type, payload, next_attempt, created_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7)
			`, ev.ID, ev.MerchantID, ev.IntentID, ev.Type, ev.Payload, now.UTC(), now.UTC())
		}
	}

	return job, tx.Commit(ctx)
}

func (s *Store) CompleteSweep(ctx context.Context, jobID string, res store.SweepResult, now time.Time) (core.SweepJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.SweepJob{}, err
	}
	defer tx.Rollback(ctx)

	var j core.SweepJob
	var leaseUntil *time.Time
	row := tx.QueryRow(ctx, `
		SELECT id, intent_id, merchant_id, deposit_address, state, version, attempts, reason, last_error,
		       next_run, lease_until, resweep, destination, chain_id, nonce, owed_micro, value_micro, charge_micro,
		       value_native, max_fee_native, raw_tx, tx_hash, block_number, gas_used, fee_native, fee_micro, margin_micro,
		       created_at, updated_at, signed_at, submitted_at, confirmed_at
		FROM sweep_jobs WHERE id = $1 FOR UPDATE
	`, jobID)
	if err := row.Scan(&j.ID, &j.IntentID, &j.MerchantID, &j.DepositAddress, &j.State, &j.Version, &j.Attempts,
		&j.Reason, &j.LastError, &j.NextRun, &leaseUntil, &j.Resweep, &j.Destination, &j.ChainID, &j.Nonce,
		&j.OwedMicro, &j.ValueMicro, &j.ChargeMicro, &j.ValueNative, &j.MaxFeeNative, &j.RawTx, &j.TxHash,
		&j.BlockNumber, &j.GasUsed, &j.FeeNative, &j.FeeMicro, &j.MarginMicro,
		&j.CreatedAt, &j.UpdatedAt, &j.SignedAt, &j.SubmittedAt, &j.ConfirmedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.SweepJob{}, store.ErrNotFound
		}
		return core.SweepJob{}, err
	}
	if j.State == core.SweepConfirmed {
		return j, nil
	}
	if j.State != core.SweepSubmitted && j.State != core.SweepSigned {
		return core.SweepJob{}, fmt.Errorf("%w: job is %s", store.ErrInvalid, j.State)
	}
	if !strings.EqualFold(res.TxHash, j.TxHash) || res.FeeNative == nil {
		return core.SweepJob{}, fmt.Errorf("%w: receipt does not match signed tx", store.ErrInvalid)
	}
	if j.ValueMicro+j.ChargeMicro != j.OwedMicro {
		return core.SweepJob{}, fmt.Errorf("%w: job amounts are inconsistent", store.ErrInvalid)
	}

	feeMicro, ok := core.CeilNativeToMicro(res.FeeNative)
	if !ok || feeMicro > j.ChargeMicro {
		return core.SweepJob{}, fmt.Errorf("%w: network fee %s exceeds reserved %s", store.ErrInvalid, res.FeeNative, core.FormatUSDC(j.ChargeMicro))
	}
	margin := j.ChargeMicro - feeMicro

	lines := []ledger.Line{
		{Account: ledger.MerchantAccount(j.MerchantID, j.IntentID), Debit: j.OwedMicro},
		{Account: ledger.DepositAccount(j.IntentID), Credit: j.ValueMicro + feeMicro},
	}
	if margin > 0 {
		lines = append(lines, ledger.Line{Account: ledger.RevenueNetworkMargin, Credit: margin})
	}
	postEntry, _, err := s.book.Post(ledger.Entry{
		Key: "sweep:" + jobID, Kind: "sweep", At: now, Lines: lines,
		Meta: map[string]string{
			"intent": j.IntentID, "merchant": j.MerchantID, "tx": strings.ToLower(j.TxHash), "destination": j.Destination,
			"value_micro": fmt.Sprint(j.ValueMicro), "network_fee_micro": fmt.Sprint(feeMicro), "reserve_micro": fmt.Sprint(j.ChargeMicro),
		},
	})
	if err != nil {
		return core.SweepJob{}, fmt.Errorf("posting sweep to ledger: %w", err)
	}

	// Persist ledger entry
	linesB, _ := json.Marshal(postEntry.Lines)
	metaB, _ := json.Marshal(postEntry.Meta)
	_, err = tx.Exec(ctx, `
		INSERT INTO ledger_entries (seq, key, kind, at, memo, meta, lines, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, postEntry.Seq, postEntry.Key, postEntry.Kind, postEntry.At, postEntry.Memo, metaB, linesB, postEntry.PrevHash, postEntry.Hash)
	if err != nil {
		return core.SweepJob{}, err
	}

	t := now.UTC()
	j.State = core.SweepConfirmed
	j.ConfirmedAt = &t
	j.BlockNumber, j.GasUsed = res.BlockNumber, res.GasUsed
	j.FeeNative, j.FeeMicro, j.MarginMicro = res.FeeNative.String(), feeMicro, margin
	j.LeaseUntil, j.UpdatedAt, j.Reason, j.LastError = time.Time{}, t, "", ""
	j.Version++

	_, err = tx.Exec(ctx, `
		UPDATE sweep_jobs SET
			state = $1, confirmed_at = $2, block_number = $3, gas_used = $4,
			fee_native = $5, fee_micro = $6, margin_micro = $7, lease_until = NULL,
			updated_at = $8, reason = '', last_error = '', version = $9
		WHERE id = $10
	`, j.State, j.ConfirmedAt, j.BlockNumber, j.GasUsed, j.FeeNative, j.FeeMicro, j.MarginMicro, j.UpdatedAt, j.Version, j.ID)
	if err != nil {
		return core.SweepJob{}, err
	}

	_, _ = tx.Exec(ctx, "DELETE FROM active_sweep_jobs WHERE intent_id = $1", j.IntentID)

	var in core.Intent
	var metaJSON []byte
	row = tx.QueryRow(ctx, "SELECT id, merchant_id, amount, received, status, deposit_address, fee_bps, customer_email, metadata, created_at, expires_at, paid_at FROM intents WHERE id = $1", j.IntentID)
	if err := row.Scan(&in.ID, &in.MerchantID, &in.Amount, &in.Received, &in.Status, &in.DepositAddress, &in.FeeBps, &in.CustomerEmail, &metaJSON, &in.CreatedAt, &in.ExpiresAt, &in.PaidAt); err == nil {
		ev := core.NewPayoutEvent(core.EventPayoutDone, &in, &j, now)
		_, _ = tx.Exec(ctx, `
			INSERT INTO deliveries (event_id, merchant_id, intent_id, event_type, payload, next_attempt, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, ev.ID, ev.MerchantID, ev.IntentID, ev.Type, ev.Payload, now.UTC(), now.UTC())

		var mc core.Merchant
		var reqAt *time.Time
		mRow := tx.QueryRow(ctx, "SELECT id, name, email, status, fee_bps, settlement_address, settlement_requested_at, email_opt_out, webhook_url, webhook_secret, created_at FROM merchants WHERE id = $1", in.MerchantID)
		if err := mRow.Scan(&mc.ID, &mc.Name, &mc.Email, &mc.Status, &mc.FeeBps, &mc.SettlementAddress, &reqAt, &mc.EmailOptOut, &mc.WebhookURL, &mc.WebhookSecret, &mc.CreatedAt); err == nil {
			for _, em := range core.EmailsFor(ev, mc, &in, nil, &j, now) {
				dataB, _ := json.Marshal(em.Data)
				_, _ = tx.Exec(ctx, `
					INSERT INTO emails (id, key, kind, to_address, merchant_id, intent_id, data, created_at, next_attempt)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
					ON CONFLICT (key) DO NOTHING
				`, em.ID, em.Key, em.Kind, em.To, em.MerchantID, em.IntentID, dataB, now.UTC(), now.UTC())
			}
		}

		if j.Resweep {
			newJob := core.SweepJob{
				ID: core.NewID("swp"), IntentID: in.ID, MerchantID: in.MerchantID, DepositAddress: in.DepositAddress,
				State: core.SweepQueued, NextRun: now.UTC(), CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
			}
			_, _ = tx.Exec(ctx, `
				INSERT INTO sweep_jobs (id, intent_id, merchant_id, deposit_address, state, next_run, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			`, newJob.ID, newJob.IntentID, newJob.MerchantID, newJob.DepositAddress, newJob.State, newJob.NextRun, newJob.CreatedAt, newJob.UpdatedAt)
			_, _ = tx.Exec(ctx, "INSERT INTO active_sweep_jobs (intent_id, job_id) VALUES ($1, $2)", in.ID, newJob.ID)
		}
	}

	return j, tx.Commit(ctx)
}

func (s *Store) RequeueSweepJob(ctx context.Context, jobID string, now time.Time) error {
	cmd, err := s.pool.Exec(ctx, `
		UPDATE sweep_jobs SET
			state = $1, version = version + 1, next_run = $2, updated_at = $3, reason = '', last_error = ''
		WHERE id = $4 AND state = $5
	`, core.SweepQueued, now.UTC(), now.UTC(), jobID, core.SweepFailed)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("%w: job not found or not in failed state", store.ErrInvalid)
	}
	return nil
}

func (s *Store) GetSweepJob(ctx context.Context, id string) (core.SweepJob, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, intent_id, merchant_id, deposit_address, state, version, attempts, reason, last_error,
		       next_run, lease_until, resweep, destination, chain_id, nonce, owed_micro, value_micro, charge_micro,
		       value_native, max_fee_native, raw_tx, tx_hash, block_number, gas_used, fee_native, fee_micro, margin_micro,
		       created_at, updated_at, signed_at, submitted_at, confirmed_at
		FROM sweep_jobs WHERE id = $1
	`, id)
	var j core.SweepJob
	var leaseUntil *time.Time
	if err := row.Scan(&j.ID, &j.IntentID, &j.MerchantID, &j.DepositAddress, &j.State, &j.Version, &j.Attempts,
		&j.Reason, &j.LastError, &j.NextRun, &leaseUntil, &j.Resweep, &j.Destination, &j.ChainID, &j.Nonce,
		&j.OwedMicro, &j.ValueMicro, &j.ChargeMicro, &j.ValueNative, &j.MaxFeeNative, &j.RawTx, &j.TxHash,
		&j.BlockNumber, &j.GasUsed, &j.FeeNative, &j.FeeMicro, &j.MarginMicro,
		&j.CreatedAt, &j.UpdatedAt, &j.SignedAt, &j.SubmittedAt, &j.ConfirmedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.SweepJob{}, store.ErrNotFound
		}
		return core.SweepJob{}, err
	}
	if leaseUntil != nil {
		j.LeaseUntil = *leaseUntil
	}
	return j, nil
}

func (s *Store) ListSweepJobs(ctx context.Context, merchantID string, limit int) ([]core.SweepJob, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := `
		SELECT id, intent_id, merchant_id, deposit_address, state, version, attempts, reason, last_error,
		       next_run, lease_until, resweep, destination, chain_id, nonce, owed_micro, value_micro, charge_micro,
		       value_native, max_fee_native, raw_tx, tx_hash, block_number, gas_used, fee_native, fee_micro, margin_micro,
		       created_at, updated_at, signed_at, submitted_at, confirmed_at
		FROM sweep_jobs
	`
	var args []any
	if merchantID != "" {
		args = append(args, merchantID)
		query += " WHERE merchant_id = $1"
	}
	query += " ORDER BY created_at DESC, id DESC LIMIT " + fmt.Sprint(limit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.SweepJob
	for rows.Next() {
		var j core.SweepJob
		var leaseUntil *time.Time
		if err := rows.Scan(&j.ID, &j.IntentID, &j.MerchantID, &j.DepositAddress, &j.State, &j.Version, &j.Attempts,
			&j.Reason, &j.LastError, &j.NextRun, &leaseUntil, &j.Resweep, &j.Destination, &j.ChainID, &j.Nonce,
			&j.OwedMicro, &j.ValueMicro, &j.ChargeMicro, &j.ValueNative, &j.MaxFeeNative, &j.RawTx, &j.TxHash,
			&j.BlockNumber, &j.GasUsed, &j.FeeNative, &j.FeeMicro, &j.MarginMicro,
			&j.CreatedAt, &j.UpdatedAt, &j.SignedAt, &j.SubmittedAt, &j.ConfirmedAt); err != nil {
			return nil, err
		}
		if leaseUntil != nil {
			j.LeaseUntil = *leaseUntil
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) OwedMicro(ctx context.Context, merchantID, intentID string) (uint64, error) {
	var mID string
	err := s.pool.QueryRow(ctx, "SELECT merchant_id FROM intents WHERE id = $1", intentID).Scan(&mID)
	if errors.Is(err, pgx.ErrNoRows) || mID != merchantID {
		return 0, store.ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.book.Balance(ledger.MerchantAccount(merchantID, intentID)), nil
}

func (s *Store) Deposits(ctx context.Context) ([]store.Deposit, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT i.id, i.merchant_id, i.deposit_address,
		       COALESCE(j.state IN ('signed', 'submitted'), false) as busy
		FROM intents i
		LEFT JOIN active_sweep_jobs a ON i.id = a.intent_id
		LEFT JOIN sweep_jobs j ON a.job_id = j.id
		ORDER BY i.id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []store.Deposit
	for rows.Next() {
		var d store.Deposit
		if err := rows.Scan(&d.IntentID, &d.MerchantID, &d.Address, &d.Busy); err != nil {
			return nil, err
		}
		d.LedgerMicro = s.book.Balance(ledger.DepositAccount(d.IntentID))
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) MerchantStats(ctx context.Context, merchantID string) (store.Stats, error) {
	var count int
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM merchants WHERE id = $1", merchantID).Scan(&count)
	if err != nil || count == 0 {
		return store.Stats{}, store.ErrNotFound
	}

	var stats store.Stats
	row := s.pool.QueryRow(ctx, `
		SELECT
			count(*),
			count(*) FILTER (WHERE status = 'pending'),
			count(*) FILTER (WHERE status = 'paid'),
			count(*) FILTER (WHERE status = 'expired'),
			COALESCE(sum(received), 0)
		FROM intents WHERE merchant_id = $1
	`, merchantID)
	_ = row.Scan(&stats.Intents, &stats.Pending, &stats.Paid, &stats.Expired, &stats.VolumeMicro)

	// Calculate total fees
	rows, err := s.pool.Query(ctx, `
		SELECT p.amount, i.fee_bps
		FROM payments p
		JOIN intents i ON p.intent_id = i.id
		WHERE i.merchant_id = $1
	`, merchantID)
	if err == nil {
		for rows.Next() {
			var amt uint64
			var bps uint32
			if err := rows.Scan(&amt, &bps); err == nil {
				if bps > 10_000 {
					bps = 10_000
				}
				stats.FeesMicro += feeOf(amt, bps)
			}
		}
		rows.Close()
	}

	s.mu.RLock()
	stats.PendingPayoutMicro = s.book.BalancePrefix(ledger.MerchantPrefix(merchantID))
	s.mu.RUnlock()

	// Sweep stats
	jRow := s.pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE state = 'confirmed'),
			count(*) FILTER (WHERE state = 'failed'),
			count(*) FILTER (WHERE state IN ('queued', 'signed', 'submitted')),
			COALESCE(sum(value_micro) FILTER (WHERE state = 'confirmed'), 0),
			COALESCE(sum(charge_micro) FILTER (WHERE state = 'confirmed'), 0)
		FROM sweep_jobs WHERE merchant_id = $1
	`, merchantID)
	_ = jRow.Scan(&stats.PayoutsConfirmed, &stats.PayoutsFailed, &stats.PayoutsInFlight, &stats.SettledMicro, &stats.NetworkFeesMicro)

	return stats, nil
}
